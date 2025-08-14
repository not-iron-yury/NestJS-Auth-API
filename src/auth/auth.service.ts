import {
  ConflictException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import bcrypt from 'bcrypt';
import { randomBytes } from 'crypto';
import { LoginDto } from 'src/auth/dto/login.dto';
import { RegisterDto } from 'src/auth/dto/register.dto';
import { UserDto } from 'src/auth/dto/user.dto';
import { PrismaService } from 'src/prisma/prisma.service';
import { HmacSha256Hex } from 'src/utils/crypto';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
  ) {}

  private async buildAccessToken(userId: number, email: string) {
    const payload = { sub: userId, email };
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

    // запить refreshToken в БД
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
      const accessToken = await this.buildAccessToken(user.id, user.email);

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
        throw new ConflictException('Email already in use');
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
    const accessToken = await this.buildAccessToken(user.id, user.email);

    // refresToken
    const refreshToken = await this.createAndStoreRefreshToken(user.id, meta);

    return {
      user: new UserDto(user),
      tokens: { accessToken, refreshToken: refreshToken },
    };
  }
}
