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
import { TooManyRequestsException } from 'src/exceptions/TooManyRequestsException';
import { EmailConfirmService } from 'src/modules/auth/email-confirm.service';
import { LoginAttemptReason } from 'src/modules/auth/enums/login-attempt-reason.enum';
import { LoginAttemptService } from 'src/modules/auth/login-attempt.service';
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
    private readonly emailConfirmService: EmailConfirmService,
    private readonly loginAttemptService: LoginAttemptService,
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

  async register(
    password: string,
    email: string,
    meta?: { ip?: string; deviceInfo?: string },
  ) {
    const hash = await bcrypt.hash(password, 10);

    try {
      const { user, refreshToken } = await this.prisma.$transaction(
        // передаем в prisma.$transaction асинхронную функцию с запросами к БД
        async (tx: PrismaService) => {
          // сохраняем пользователя в БД
          const user = await tx.user.create({
            data: { email, hash },
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
      await this.emailConfirmService.sendEmailVerifikation(user.email, meta);

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

  async login(
    email: string,
    password: string,
    meta?: { ip?: string; deviceInfo?: string },
  ) {
    // 1) определяем константы: лимит попыток, вермя блокировки, временное окно
    const maxAttempt = Number(this.config.get('LOGIN_MAX_ATTEMPTS') ?? 5);
    const lockMin = Number(this.config.get('LOCK_TIME_MINUTES') ?? 15);
    const windowMin = Number(
      this.config.get('LOGIN_ATTEMPT_WINDOW_MINUTES') ?? 15,
    );

    // 2) узначем количество последних неудачных попыток
    const failed = await this.loginAttemptService.countFailedAttempts(
      email,
      windowMin,
    );

    // 3) если достигнут лимит - выбрасываем исключение
    if (failed >= maxAttempt) {
      throw new TooManyRequestsException(
        'Слишком много неудачных попыток входа в систему. Повторите попытку позже.',
      );
    }

    //  3) пытаемся найти пользователя
    const user = await this.prisma.user.findUnique({
      where: { email },
    });

    //  4) если пользователь не найден - записываем попытку входа (без userID) и выбрасываем исключение
    if (!user) {
      await this.loginAttemptService.recordAttempt({
        email,
        userId: null,
        ip: meta?.ip,
        userAgent: meta?.deviceInfo,
        success: false,
        reason: LoginAttemptReason.USER_NOT_FOUND,
      });
      throw new UnauthorizedException('Такой пользователь не существует');
    }

    // 5) сравниваем хеши паролей
    const isValidPassword = await bcrypt.compare(password, user.hash);

    // 6) если пароль не валидный - записываем попытку входа (c userId) и выбрасываем исключение
    if (!isValidPassword) {
      await this.loginAttemptService.recordAttempt({
        email,
        userId: user.id,
        ip: meta?.ip,
        userAgent: meta?.deviceInfo,
        success: false,
        reason: LoginAttemptReason.INVALID_PASSWORD,
      });

      // повторно проверяем лимит неудачных попыток (т.к. пользователь был найден)
      if (failed >= maxAttempt) {
        // блокируем пользователя или выполняем иные действия
      }
      throw new UnauthorizedException('Неправильные данные');
    }

    // 7) записываем успешную попытку входа
    await this.loginAttemptService.recordAttempt({
      email,
      userId: user.id,
      ip: meta?.ip,
      userAgent: meta?.deviceInfo,
      success: true,
      reason: LoginAttemptReason.OK,
    });

    // 8) Опиционально. Тут можно удалить старые записи, или данные можно сохранить для аудита.
    await this.loginAttemptService.deleteOlderThan(5);

    // 9) создаем accessToken
    const accessToken = await this.buildAccessToken(
      user.id,
      user.email,
      user.role,
    );

    // 10) создаем refresToken
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
}
