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

  async register(
    dto: RegisterDto,
    meta?: { ip?: string; deviceInfo?: string },
  ) {
    const hash = await bcrypt.hash(dto.password, 10);

    try {
      const result = await this.prisma.$transaction(async (tx) => {
        const user = await tx.user.create({
          data: {
            email: dto.email,
            hash,
          },
        });

        // генерация refresh токена
        const rawRefreshToken = randomBytes(40).toString('hex');
        const hashedRefreshToken = HmacSha256Hex(rawRefreshToken);

        // дата истечения
        const expiresAt = new Date();
        expiresAt.setDate(
          expiresAt.getDate() +
            Number(this.config.get('REFRESH_TOKEN_EXPIRES_IN')),
        );

        await tx.refreshToken.create({
          data: {
            userId: user.id,
            token: hashedRefreshToken,
            expiresAt,
            createdByIp: meta?.ip,
            deviceInfo: meta?.deviceInfo,
          },
        });

        return { user, rawRefreshToken };
      });

      // генерация access token
      const payload = { sub: result.user.id, email: result.user.email };
      const accessToken = await this.jwt.signAsync(payload);

      return {
        user: new UserDto(result.user),
        access_token: accessToken,
        refresh_token: result.rawRefreshToken,
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

    // формируем access token
    const tokens = await this.generateTokens(user, meta);

    return {
      user: new UserDto(user),
      tokens,
    };
  }

  private async generateTokens(
    user: { id: number; email: string },
    meta?: { ip?: string; deviceInfo?: string },
  ) {
    // 1) Access Token
    const payload = { sub: user.id, email: user.email };
    const accessToken = await this.jwt.signAsync(payload); // второй параметр (options) подтягивается из DI Jwt config

    // 2) Refresh Token
    const rawToken = randomBytes(40).toString('hex'); // сырой токен
    const hashedToken = HmacSha256Hex(rawToken); // хэш токена

    // 3) дата истечения
    const expiresAt = new Date();
    expiresAt.setDate(
      expiresAt.getDate() + Number(this.config.get('REFRESH_TOKEN_EXPIRES_IN')),
    );

    // 4) записываем Refresh Token в БД
    await this.prisma.refreshToken.create({
      data: {
        userId: user.id,
        token: hashedToken,
        expiresAt,
        createdByIp: meta?.ip || null,
        deviceInfo: meta?.deviceInfo || null,
      },
    });

    // 5) возвращаем оба токена
    return {
      accessToken,
      refreshToken: hashedToken, // клиенту возвращаем сырой вариант
    };
  }
}
