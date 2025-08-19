import {
  BadRequestException,
  ConflictException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import type { Role } from '@prisma/client';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import bcrypt from 'bcrypt';
import { randomBytes } from 'crypto';
import { LoginDto } from 'src/modules/auth/dto/login.dto';
import { RegisterDto } from 'src/modules/auth/dto/register.dto';
import { MailService } from 'src/modules/mail/mail.service';
import { UserDto } from 'src/modules/user/dto/user.dto';
import { PrismaService } from '../../prisma/prisma.service';
import { HmacSha256Hex } from '../../utils/crypto';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
    private readonly mailService: MailService,
  ) {}

  private async buildAccessToken(userId: number, email: string, role: Role) {
    const payload = { sub: userId, email, role };
    return await this.jwt.signAsync(payload);
  }

  private async createAndStoreRefreshToken(
    userId: number,
    meta?: { ip?: string; deviceInfo?: string },
    tx = this.prisma, // можно передавать PrismaTransactionClient для транзакции
  ) {
    // генерация refresh токена
    const rawToken = randomBytes(40).toString('hex');
    const hashedToken = HmacSha256Hex(rawToken);

    // дата истечения
    const expiresAt = new Date();
    expiresAt.setDate(
      expiresAt.getDate() + Number(this.config.get('REFRESH_TOKEN_EXPIRES_IN')),
    );

    // сохраняем refreshToken в БД
    await tx.refreshToken.create({
      data: {
        userId,
        token: hashedToken,
        expiresAt,
        createdByIp: meta?.ip || null,
        deviceInfo: meta?.deviceInfo || null,
      },
    });

    return rawToken;
  }

  async sendEmailVerifikation(
    email: string,
    meta?: { ip?: string; deviceInfo?: string },
  ) {
    // 1) получаем email пользователя
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user) {
      throw new BadRequestException('Пользователь с таким email не найден');
    }

    // 2) если пользователь уже активен
    if (user.isActive) return { message: 'Email уже подтвержден' };

    // 3) генерируем сырой emailToken и хэшируем его
    const rawToken = randomBytes(40).toString('hex');
    const hashedToken = HmacSha256Hex(rawToken);

    // 4) вычисляем expiresAt
    const expiresAt = new Date();
    expiresAt.setHours(
      expiresAt.getHours() + Number(this.config.get('EMAIL_TOKEN_TTL_HOURS')),
    );

    // 5) сохраняем в БД новый хэш emailToken и отменяем старые
    await this.prisma.$transaction(async (tx) => {
      // маркируем все предыдущие токены пользователя как использованные (не действительные)
      await tx.emailVerificationToken.updateMany({
        where: { userId: user.id, used: false },
        data: { used: true },
      });

      // создаем новый emailToken
      await tx.emailVerificationToken.create({
        data: {
          userId: user.id,
          token: hashedToken,
          expiresAt,
          createdByIp: meta?.ip || null,
          deviceInfo: meta?.deviceInfo || null,
        },
      });
    });

    // 6) создаем ссыль подтверждения
    const appUrl = this.config.get('APP_URL') as string;
    const link = `${appUrl}/auth/confirm-email?token=${rawToken}`; // в ссылке для подтверждения сырой токен

    // 7) отправка письма (эмуляция) - вызываем MailService и просто выполняем логирование
    this.mailService.sendVerificationEmail(String(user.email), link, meta);

    // 8) возврат (пока так)
    return { message: 'Verification email sent', link: link };
  }

  async register(
    dto: RegisterDto,
    meta?: { ip?: string; deviceInfo?: string },
  ) {
    const hash = await bcrypt.hash(dto.password, 10);

    try {
      const { user, refreshToken } = await this.prisma.$transaction(
        // передаем в prisma.$transaction асинхронную функцию с запросами к БД
        async (tx: PrismaService) => {
          // сохраняем пользователя в БД
          const user = await tx.user.create({
            data: { email: dto.email, hash },
          });

          // сохраняем refreshToken в БД
          const refreshToken = await this.createAndStoreRefreshToken(
            user.id,
            meta,
            tx, // все запросы, выполненные через объект tx, попадают внутрь общей транзакции
          );

          // возвр. пользователя и сырой токен
          return { user, refreshToken };
        },
      );

      // создаем accessToken
      const accessToken = await this.buildAccessToken(
        user.id,
        user.email,
        user.role,
      );

      // ссылка на подтверждение почты
      await this.sendEmailVerifikation(user.email, meta);

      // возвр. структурированных данных пользователя и двух токенов
      return {
        user: new UserDto(user),
        tokens: { accessToken, refreshToken },
      };
    } catch (error) {
      if (
        error instanceof PrismaClientKnownRequestError &&
        error.code === 'P2002'
      ) {
        throw new ConflictException('Такой email уже используется');
      }
      throw error;
    }
  }

  async login(dto: LoginDto, meta?: { ip?: string; deviceInfo?: string }) {
    // проверяем пользователя
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });
    if (!user)
      throw new UnauthorizedException('Такой пользователь не существует');

    // сравниваем хеши паролей
    const isValidPassword = await bcrypt.compare(dto.password, user.hash);
    if (!isValidPassword)
      throw new UnauthorizedException('Неправильные данные');

    // accessToken
    const accessToken = await this.buildAccessToken(
      user.id,
      user.email,
      user.role,
    );

    // refresToken
    const refreshToken = await this.createAndStoreRefreshToken(user.id, meta);

    return {
      user: new UserDto(user),
      tokens: { accessToken, refreshToken: refreshToken },
    };
  }

  async refresh(
    rawRefreshToken: string,
    meta?: { ip?: string; deviceInfo?: string },
  ) {
    if (!rawRefreshToken) {
      throw new BadRequestException('Refresh token обязателен');
    }

    // хэшируем сырой токен
    const hashed = HmacSha256Hex(rawRefreshToken);

    // берем токен из БД и связанные с ним данные пользователя
    const existing = await this.prisma.refreshToken.findUnique({
      where: { token: hashed }, // условие выбора
      include: { user: true }, // включение связанных записей из таблицы user
    });

    // если токен не найден или не найдены связанные с ним данные
    if (!existing || !existing.user) {
      throw new UnauthorizedException('Неправильный refresh token');
    }
    // если токен уже отозван
    if (existing.revoked) {
      throw new UnauthorizedException('Refresh token отозван');
    }
    // если истек срок годности
    if (
      existing.createdAt <=
      new Date(
        new Date().getDate() +
          Number(this.config.get('REFRESH_TOKEN_EXPIRES_IN')),
      )
    ) {
      throw new UnauthorizedException('Refresh token просрочен');
    }

    // Ротация одной транзакцией
    const updateRefreshToken = async (tx: PrismaService) => {
      // ревок старого токена
      await tx.refreshToken.update({
        where: { token: hashed },
        data: { revoked: true },
      });

      // новый refresh (сырой в переменную, хэшированный в БД)
      const newRawRefres = await this.createAndStoreRefreshToken(
        existing.userId,
        meta,
        tx,
      );
      // новый access
      const newAccess = await this.buildAccessToken(
        existing.user.id,
        existing.user.email,
        existing.user.role,
      );

      return {
        user: new UserDto(existing.user),
        tokens: {
          accessToken: newAccess,
          refreshToken: newRawRefres,
        },
      };
    };
    const result = await this.prisma.$transaction(updateRefreshToken);
    return result;
  }

  async revok(rawRefreshToken: string) {
    if (!rawRefreshToken) {
      throw new BadRequestException('Refresh token обязателен');
    }

    const hashed = HmacSha256Hex(rawRefreshToken);
    const existing = await this.prisma.refreshToken.findUnique({
      where: { token: hashed },
    });

    // если не найден
    if (!existing) {
      throw new UnauthorizedException('Неправильный refresh token');
    }
    // если уже отозван
    if (existing.revoked) {
      return; // ничего не делаем, т.к. токен уже отозван
    }

    // ревок старого токена
    await this.prisma.refreshToken.update({
      where: { token: hashed },
      data: { revoked: true },
    });

    return;
  }

  async confirmEmail(token: string) {
    // 1) берем из БД токен и связанный с ним user
    const hashed = HmacSha256Hex(token);
    const verifiedToken = await this.prisma.emailVerificationToken.findUnique({
      where: { token: hashed },
      include: { user: true },
    });

    // 2) проверяем существование токена
    if (!verifiedToken) {
      throw new BadRequestException('Несуществующий email токен');
    }

    // 3) проверяем срок годности токена
    if (verifiedToken.expiresAt < new Date()) {
      throw new BadRequestException('Email токен просрочен');
    }

    // 4) подтверждаем пользователя
    await this.prisma.user.update({
      where: { id: verifiedToken.userId },
      data: { isActive: true },
    });

    // 5) удаляем использованный токен (больше в нем необходимости нет)
    await this.prisma.emailVerificationToken.delete({
      where: { id: verifiedToken.id },
    });

    // 6) возвращаем сообщение
    return { message: 'Email подтвержден' };
  }
}
