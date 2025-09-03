import { BadRequestException, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PhoneService } from 'src/modules/phone/phone.service';
import { PrismaService } from '../../prisma/prisma.service';
import { HmacSha256Hex, generateSms } from '../../utils/crypto';

@Injectable()
export class PhoneConfirmService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
    private readonly phoneService: PhoneService,
  ) {}

  async sendVerifikationSms(
    phone: string,
    meta?: { ip?: string; deviceInfo?: string },
  ) {
    // 1) пробуем найти пользователя
    const user = await this.prisma.user.findUnique({ where: { phone } });
    if (!user) {
      throw new BadRequestException(
        'PhoneVerifikation: пользователь не найден',
      );
    }

    // 2) если пользователь уже активен
    if (user.isActive) return { message: 'Пользователь уже верифицирован' };

    // 3) генерируем сырой phone code и хэшируем его
    const rawCode = generateSms();
    const hashedCode = HmacSha256Hex(rawCode);

    // 4) вычисляем expiresAt
    const expiresAt = new Date();
    expiresAt.setMinutes(
      expiresAt.getMinutes() + Number(this.config.get('SMS_TOKEN_TTL_HOURS')),
    );

    // 5) сохраняем в БД новый хэш sms code и отменяем старые
    await this.prisma.$transaction(async (tx) => {
      // маркируем все предыдущие токены пользователя как использованные (не действительные)
      await tx.phoneVerificationToken.updateMany({
        where: { userId: user.id, used: false },
        data: { used: true },
      });

      // создаем новый sms code
      await tx.phoneVerificationToken.create({
        data: {
          userId: user.id,
          token: hashedCode,
          expiresAt,
          createdByIp: meta?.ip || null,
          deviceInfo: meta?.deviceInfo || null,
        },
      });
    });

    // 6) отправка SMS (эмуляция) - вызываем MailService и просто выполняем логирование
    this.phoneService.sendVerificationPhone(String(user.phone), rawCode);
  }

  async confirmPhone(userId: number, code: string) {
    // 1) берем из БД токен верификации номера телефона и связанный с ним user
    const hashed = HmacSha256Hex(code);
    const verified = await this.prisma.phoneVerificationToken.findUnique({
      where: {
        // используем имя составного индекса (генерируется автоматически) userId_token
        userId_token: {
          userId: userId,
          token: hashed,
        },
      },
      include: { user: true },
    });
    // 2) проверяем существование кода
    if (!verified) {
      throw new BadRequestException('Несуществующий SMS код');
    }

    // 3) проверяем срок годности токена
    if (verified.expiresAt < new Date()) {
      throw new BadRequestException('SMS код просрочен');
    }

    await this.prisma.$transaction(async (tx) => {
      // 4) подтверждаем пользователя
      await tx.user.update({
        where: { id: verified.userId },
        data: { isActive: true },
      });

      // 5) маркируем SMS код как использованный
      await tx.phoneVerificationToken.update({
        where: { id: verified.id },
        data: { used: true },
      });
    });

    // 6) возвращаем сообщение
    return { message: 'Пользователь верифицирован' };
  }
}
