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
import { RedisService } from 'src/common/redis/redis.service';
import { ClientType } from 'src/common/types/client-type.enum';
import { TooManyRequestsException } from 'src/exceptions/TooManyRequestsException';
import { EmailConfirmService } from 'src/modules/auth/email-confirm.service';
import { LoginAttemptReason } from 'src/modules/auth/enums/login-attempt-reason.enum';
import { LoginAttemptService } from 'src/modules/auth/login-attempt.service';
import { UserDto } from 'src/modules/user/dto/user.dto';
import { v4 as uuidv4 } from 'uuid';
import { PrismaService } from '../../prisma/prisma.service';
import { HmacSha256Hex } from '../../utils/crypto';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
    private readonly emailConfirmService: EmailConfirmService,
    private readonly loginAttemptService: LoginAttemptService,
    private readonly redis: RedisService,
  ) {}

  private async createAccessToken(userId: number, email: string, role: Role) {
    const payload = { sub: userId, email, role };
    return await this.jwt.signAsync(payload);
  }

  private async createAndStoreRefreshToken(
    userId: number,
    deviceId: string,
    clientType: ClientType,
    meta?: { ip?: string; deviceInfo?: string },
    tx = this.prisma,
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
        deviceId,
        userId,
        token: hashedToken,
        expiresAt,
        createdByIp: meta?.ip || null,
        deviceInfo: meta?.deviceInfo || null,
        clientType,
      },
    });

    return rawToken;
  }

  async register(
    password: string,
    email: string,
    deviceId: string = uuidv4(), // получаем ранее созданный от клиента или генерируем новый
    clientType: ClientType,
    meta?: { ip?: string; deviceInfo?: string },
  ) {
    // хэш пароля
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
            deviceId,
            clientType,
            meta,
            tx, // все запросы, выполненные через объект tx, попадают внутрь общей транзакции
          );

          // возвр. пользователя и сырой токен
          return { user, refreshToken };
        },
      );

      // создаем accessToken
      const accessToken = await this.createAccessToken(
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
        deviceId,
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
    deviceId: string = uuidv4(), // получаем ранее созданный от клиента или генерируем новый
    clientType: ClientType,
    meta?: { ip?: string; deviceInfo?: string },
  ) {
    // константы для работы с email
    const maxAttempt = Number(this.config.get('LOGIN_MAX_ATTEMPTS') ?? 5);
    const lockMin = Number(this.config.get('LOCK_TIME_MINUTES') ?? 15);
    const windowMin = Number(
      this.config.get('LOGIN_ATTEMPT_WINDOW_MINUTES') ?? 15,
    );

    // константы для работы с IP
    const ip = meta?.ip || 'unknown';
    const ipWindowSec =
      Number(this.config.get('LOGIN_IP_WINDOW_MINUTES') ?? 15) * 60;
    const ipLockSec =
      Number(this.config.get('LOGIN_IP_LOCK_MINUTES') ?? 15) * 60;
    const ipMaxAttempts = Number(
      this.config.get('LOGIN_MAX_ATTEMPTS_BY_IP') ?? 50,
    );

    // 1)  проверяем, заблокирован ли IP
    if (await this.redis.isIpBlocked(ip)) {
      throw new TooManyRequestsException(
        'Слишком много запросов с вашего IP. Попробуйте позже.',
      );
    }

    //  2) ищем пользователя (нужен для проверки lockedUntil и записи userId в лог)
    const user = await this.prisma.$transaction(async (tx: PrismaService) => {
      // пытаемся найти
      const existing = await tx.user.findUnique({ where: { email } });
      //  если не найден - записываем неудачную попытку входа (без userID)
      if (!existing) {
        await this.loginAttemptService.recordAttempt(
          {
            email,
            userId: null,
            ip: meta?.ip,
            userAgent: meta?.deviceInfo,
            success: false,
            reason: LoginAttemptReason.USER_NOT_FOUND,
          },
          tx,
        );
        return false;
      }
      return existing;
    });

    //  3) если пользователь не найден
    if (!user) {
      const ipFails = await this.redis.incrFail(ip, ipWindowSec); // увеличиваем счетчик неудачных попыток для IP

      if (ipFails >= ipMaxAttempts) {
        await this.redis.blockIp(ip, ipLockSec); // если превышен лимит попыток для IP - блокируем по IP
        throw new TooManyRequestsException(
          'Слишком много запросов с вашего IP. Попробуйте позже.',
        );
      }

      throw new UnauthorizedException('Неверные учетные данные');
    }

    // 4) если пользователь найден, но он заблокирован
    if (user?.lockedUntil && user.lockedUntil > new Date()) {
      throw new TooManyRequestsException(
        `Аккаунт заблокирован. Повторите попытку через ${lockMin} минут.`,
      );
    }

    // 5) если пользователь найден и не заблокирован:
    const isValidPassword = await bcrypt.compare(password, user.hash);

    // 5-1) если пароль не валидный
    if (!isValidPassword) {
      // работа с email
      await this.prisma.$transaction(async (tx) => {
        //  записываем попытку входа (c userId)
        await tx.loginAttempt.create({
          data: {
            email,
            userId: user.id,
            ip: meta?.ip,
            userAgent: meta?.deviceInfo,
            success: false,
            reason: LoginAttemptReason.INVALID_PASSWORD,
          },
        });

        // считаем количество неудачных попыток за временное окно
        const since = new Date(Date.now() - windowMin * 60 * 1000);
        const failed = await tx.loginAttempt.count({
          where: {
            email,
            success: false,
            createdAt: { gte: since }, // "все записи, у которых createdAt >= since" | gte = "greater than or equal" (больше или равно)
          },
        });

        // блокируем, если лимит превышен
        if (failed >= maxAttempt) {
          // вычисляем дату окончания блокировки
          const lockedUntil = new Date();
          lockedUntil.setMinutes(lockedUntil.getMinutes() + lockMin);

          // блокируем до lockedUntil
          await tx.user.update({
            where: { id: user.id },
            data: { lockedUntil },
          });
        }
      });

      // работа с IP
      const ipFails = await this.redis.incrFail(ip, ipWindowSec); // увеличиваем счетчик неудачных попыток для IP
      if (ipFails >= ipMaxAttempts) {
        await this.redis.blockIp(ip, ipLockSec); // если превышен лимит попыток для IP - блокируем по IP
        throw new TooManyRequestsException(
          'Слишком много запросов с вашего IP. Попробуйте позже.',
        );
      }

      throw new UnauthorizedException('Неправильные данные');
    }

    // 5-2) если пароль валидный
    // записываем успешную попытку входа
    await this.loginAttemptService.recordAttempt({
      email,
      userId: user.id,
      ip: meta?.ip,
      userAgent: meta?.deviceInfo,
      success: true,
      reason: LoginAttemptReason.OK,
    });
    // сбрасываем счетчик неудачных попыток авторизоваться для текущего IP
    await this.redis.delFail(ip);

    // 6) создаем токены
    const refreshToken = await this.createAndStoreRefreshToken(
      user.id,
      deviceId,
      clientType,
      meta,
    );
    const accessToken = await this.createAccessToken(
      user.id,
      user.email,
      user.role,
    );

    return {
      user: new UserDto(user),
      tokens: { accessToken, refreshToken: refreshToken },
      deviceId,
    };
  }

  async refresh(
    rawRefreshToken: string,
    clientType: ClientType,
    meta?: { ip?: string; deviceInfo?: string },
  ) {
    if (!rawRefreshToken) {
      throw new BadRequestException('Refresh token обязателен');
    }

    // 1) хэшируем сырой токен
    const hashed = HmacSha256Hex(rawRefreshToken);

    // 2) берем токен из БД и связанные с ним данные пользователя
    const existing = await this.prisma.refreshToken.findUnique({
      where: { token: hashed },
      include: { user: true }, // включение связанных записей из таблицы user
    });

    // 3) проверочки
    if (!existing || !existing.user) {
      throw new UnauthorizedException('Неправильный refresh token'); // если не найден токен или связанный с ним user
    }
    if (existing.revoked) {
      throw new UnauthorizedException('Refresh token отозван'); // если токен был отозван ранее
    }
    if (existing.expiresAt <= new Date()) {
      throw new UnauthorizedException('Refresh token просрочен'); // если истек срок годности токена
    }

    // 4) если ОК - отменяем старый токен и создаем новую пару (одной транзакцией)
    return await this.prisma.$transaction(async (tx: PrismaService) => {
      // ревок старого токена
      await tx.refreshToken.update({
        where: { token: hashed },
        data: { revoked: true },
      });

      // новый refresh
      const newRawRefres = await this.createAndStoreRefreshToken(
        existing.userId,
        existing.deviceId,
        clientType,
        meta,
        tx,
      );
      // новый access
      const newAccess = await this.createAccessToken(
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
    });
  }

  async revokByToken(rawRefreshToken: string) {
    if (!rawRefreshToken) {
      throw new BadRequestException('Refresh token обязателен');
    }

    // 1) хэшируем полученный сырой токен и проверяем его наличие в БД
    const hashed = HmacSha256Hex(rawRefreshToken);
    const existing = await this.prisma.refreshToken.findUnique({
      where: { token: hashed },
    });

    // 2) если не найден
    if (!existing) {
      throw new UnauthorizedException('Неправильный refresh token');
    }
    // 3) если уже отозван
    if (existing.revoked) {
      return; // ничего не делаем, т.к. токен уже отозван
    }

    // 4) отзываем токен
    await this.prisma.refreshToken.update({
      where: { token: hashed },
      data: { revoked: true },
    });

    return;
  }

  async revok(deviceId: string) {
    return this.prisma.refreshToken.updateMany({
      where: { deviceId, revoked: false },
      data: { revoked: true },
    });
  }

  async getSessions(userId: number) {
    return this.prisma.refreshToken.findMany({
      where: { userId, revoked: false },
      select: {
        id: true,
        deviceId: true,
        deviceInfo: true,
        createdAt: true,
        expiresAt: true,
      },
    });
  }
}
