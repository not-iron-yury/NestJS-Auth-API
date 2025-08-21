import { BadRequestException, Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import bcrypt from 'bcrypt';
import { randomBytes } from 'crypto';
import { MailService } from 'src/modules/mail/mail.service';
import { PrismaService } from 'src/prisma/prisma.service';
import { HmacSha256Hex } from 'src/utils/crypto';

@Injectable()
export class PasswordResetSevice {
  private readonly logger = new Logger(PasswordResetSevice.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
    private readonly mailService: MailService,
  ) {}

  // Инициализация сброса пароля
  async requestPasswordReset(
    email: string,
    meta?: { ip?: string; deviceInfo?: string },
  ) {
    // 1) проверяем пользователя в БД
    const user = await this.prisma.user.findUnique({
      where: { email },
    });

    // 2) всегда! возвращаем success: true (без лишней информации)
    //    ошибку не выбрасываем - не палим, что полученный email отсутствует в БД
    //    продолжаем только если пользователь существует
    if (!user) {
      this.logger.debug(
        `Запрос на сброс пароля для несуществующего email: ${email}`,
      );
      return { success: true }; // фейковое подтверждение
    }

    // 3) создаем passwordResetToken (сырой и хэш)
    const rawToken = randomBytes(32).toString('hex');
    const hashToken = HmacSha256Hex(rawToken);

    // 4) вычисляем expiresAt
    const expiresAt = new Date();
    expiresAt.setHours(
      expiresAt.getHours() +
        Number(this.config.get('PASSWORD_RESET_TTL_HOURS')) || 1,
    );

    // 5) создаем новый passwordResetToken и отменяем старые
    await this.prisma.$transaction(async (tx) => {
      // старые отмечаем как использованные
      await tx.passwordResetToken.updateMany({
        where: { userId: user.id, used: false },
        data: { used: true, usedAt: new Date() },
      });

      // создаем новый
      await tx.passwordResetToken.create({
        data: {
          userId: user.id,
          token: hashToken,
          expiresAt,
          createdByIp: meta?.ip,
          deviceInfo: meta?.deviceInfo,
        },
      });
    });

    // 6) создаем ссылку для письма на сброс пароля
    const appUrl = this.config.get('APP_URL') as string;
    const link = `${appUrl}/auth/verify-password-reset?token=${rawToken}`; // в ссылке именно сырой токен

    // 7) отправляем письмо (пока что эмуляция)
    this.mailService.sendPasswordResetEmail(String(user.email), link, meta);

    // 8) настоящее подтверждение
    return { success: true };
  }

  // Проверка токена сброса пароля (наличие и действительность)
  async verifyResetToken(token: string) {
    // 1) хэшируем полученный токен
    const hashed = HmacSha256Hex(token);

    // 2) проверяем существование в БД
    const existing = await this.prisma.passwordResetToken.findUnique({
      where: { token: hashed },
      // include: { user: true }, // можем потянуть еще и данные пользователя, если что
    });

    //4) проверочки
    if (!existing) throw new BadRequestException('Несуществующий токен');
    if (existing.used) {
      throw new BadRequestException('Токен уже был использован');
    }
    if (existing.expiresAt < new Date()) {
      throw new BadRequestException('Просроченный токен');
    }

    return { valid: true }; // можно вернуть отдельные даныне пользователя, если что
  }

  // Сброс пароля
  async resetePassword(
    rawToken: string,
    newPassword: string,
    meta?: { ip?: string; deviceInfo?: string },
  ) {
    // 1) хэшируем полученный сырой токен (для последующей проверки)
    const hashedToken = HmacSha256Hex(rawToken);

    // 2) проверяем токен в БД и получаем данные пользователя
    const existing = await this.prisma.passwordResetToken.findUnique({
      where: { token: hashedToken },
      include: { user: true }, // нам понадобится хэш текущего (старого) старого пароля
    });

    // 3) проверочки
    if (!existing) throw new BadRequestException('Несуществующий токен');
    if (existing.used) {
      throw new BadRequestException('Токен уже был использован');
    }
    if (existing.expiresAt < new Date()) {
      throw new BadRequestException('Просроченный токен');
    }

    // 4) сравниваем новый и старый пароли
    const isSame = await bcrypt.compare(newPassword, existing.user.hash);
    if (isSame) {
      throw new BadRequestException(
        'Новый пароль должен отличаться от предыдущего',
      );
    }

    // 5) хэшируем новый пароль
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // 6) транзакция (меняем данные в БД)
    await this.prisma.$transaction(async (tx) => {
      // обновляем пароль пользователя
      await tx.user.update({
        where: { id: existing.userId },
        data: { hash: hashedPassword },
      });

      // отмечаем токен смены пароля как использованный
      await tx.passwordResetToken.update({
        where: { id: existing.id },
        data: { used: true, usedAt: new Date() },
      });

      // отзываем все refresh токены пользователя
      await tx.refreshToken.updateMany({
        where: { userId: existing.userId, revoked: false },
        data: { revoked: true },
      });
    });

    // 7) опционально - логирование или уведомление на почту
    this.logger.log(
      `Password reset for userId=${existing.userId} (ip=${meta?.ip ?? 'unknown'})`,
    );

    // 8)
    return { success: true };
  }
}
