import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class LoginAttemptService {
  constructor(private readonly prisma: PrismaService) {}

  // записываем попытку залогиниться в БД
  async recordAttempt(params: {
    email: string;
    userId?: number | null;
    ip?: string | null;
    userAgent?: string | null;
    success: boolean;
    reason?: string | null;
  }) {
    await this.prisma.loginAttempt.create({
      data: {
        email: params.email,
        userId: params.userId ?? null,
        ip: params.ip ?? null,
        userAgent: params.userAgent ?? null,
        success: params.success ?? null,
        reason: params.reason ?? null,
      },
      select: { id: true, success: true },
    });
  }

  // подсчитываем количество неудачных попыток отправки электронной почты за последние `windowMinutes` минут
  async countFailedAttempts(
    email: string,
    windowMinutes: number,
  ): Promise<number> {
    // 1)
    const since = new Date(Date.now() - windowMinutes * 60 * 1000);

    // 2) считаем количество записей в таблице login_attempt и возвращаем их число
    const result = await this.prisma.loginAttempt.count({
      where: {
        email,
        success: false,
        createdAt: { gte: since }, // условие "все записи, у которых createdAt >= since"
        // gte = "greater than or equal" (больше или равно)
      },
    });
    return result;
  }

  // опцииональный helper - удаляет в БД устаревшие записи попыток злогиниться
  async deleteOlderThan(days: number) {
    // 1)  определяем крайнюю дату с учетом указанного количества дней
    const since = new Date();
    since.setDate(since.getDate() - days);

    // 2) удаялем все записи в БД до крайней даты, и оставляем записи только за последние <days> дней.
    await this.prisma.loginAttempt.deleteMany({
      where: { createdAt: { lt: since } }, // условие "все записи, у которых createdAt < since"
    });
  }
}
