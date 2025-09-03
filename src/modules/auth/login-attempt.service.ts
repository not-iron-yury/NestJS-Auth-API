import { Injectable } from '@nestjs/common';
import { AuthType } from '@prisma/client';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class LoginAttemptService {
  constructor(private readonly prisma: PrismaService) {}

  // записываем попытку залогиниться в БД
  async recordAttempt(
    params: {
      identifier: string;
      authType: AuthType;
      userId?: number | null;
      ip?: string | null;
      userAgent?: string | null;
      success: boolean;
      reason?: string | null;
    },
    tx: PrismaService = this.prisma,
  ) {
    await tx.loginAttempt.create({
      data: {
        identifier: params.identifier,
        type: params.authType,
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
    identifier: string,
    windowMinutes: number,
    tx: PrismaService = this.prisma,
  ): Promise<number> {
    // 1)
    const since = new Date(Date.now() - windowMinutes * 60 * 1000);

    // 2) считаем количество записей в таблице login_attempt и возвращаем их число
    const result = await tx.loginAttempt.count({
      where: {
        identifier,
        success: false,
        createdAt: { gte: since }, // условие "все записи, у которых createdAt >= since"
        // gte = "greater than or equal" (больше или равно)
      },
    });
    return result;
  }

  // опцииональный helper - удаляет в БД устаревшие записи попыток злогиниться
  async deleteOlderThan(days: number, tx: PrismaService = this.prisma) {
    const since = new Date();
    since.setDate(since.getDate() - days);

    const countDeleted = await tx.loginAttempt.deleteMany({
      where: { createdAt: { lt: since } },
    });

    return countDeleted;
  }
}
