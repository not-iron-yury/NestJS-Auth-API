import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class RefreshTokenCleanupService {
  private readonly logger = new Logger(RefreshTokenCleanupService.name);

  constructor(private readonly prisma: PrismaService) {}

  @Cron(CronExpression.EVERY_3_HOURS)
  async handleCleanup() {
    const result = await this.prisma.refreshToken.deleteMany({
      where: {
        revoked: true,
      },
    });
    console.log(`Удалено ${result.count} просроченных refresh-токенов`);

    if (result.count > 0) {
      this.logger.log(`Удалено ${result.count} просроченных refresh-токенов`);
    }
  }
}
