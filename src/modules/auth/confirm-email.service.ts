import { BadRequestException, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { randomBytes } from 'crypto';
import { MailService } from 'src/modules/mail/mail.service';
import { PrismaService } from '../../prisma/prisma.service';
import { HmacSha256Hex } from '../../utils/crypto';

@Injectable()
export class EmailConfirmService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
    private readonly mailService: MailService,
  ) {}

  // Генерирует новый EmailVerificationToken и link, которые отправляются на email пользователя
  async sendEmailVerification(
    email: string,
    meta?: { ip?: string; deviceInfo?: string },
  ) {
    // 1) получаем email пользователя
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user || !user.email) {
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
    this.mailService.sendVerificationEmail(user.email, link, meta);

    // 8) возврат (пока так)
    return { message: 'Verification email sent', link: link };
  }

  // Валидация полученного от клиента EmailVerificationToken и подтверждение пользователя (isActive: true)
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

    await this.prisma.$transaction(async (tx) => {
      // 4) подтверждаем пользователя
      await tx.user.update({
        where: { id: verifiedToken.userId },
        data: { isActive: true },
      });

      // 5) маркируем токен как использованный
      await tx.emailVerificationToken.update({
        where: { id: verifiedToken.id },
        data: { used: true },
      });
    });

    // 6) возвращаем сообщение
    return { message: 'Email подтвержден' };
  }
}
