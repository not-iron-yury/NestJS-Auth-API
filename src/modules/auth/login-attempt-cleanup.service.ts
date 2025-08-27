import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { LoginAttemptService } from 'src/modules/auth/login-attempt.service';

@Injectable()
export class LoginAttemptCleanupService {
  private readonly logger = new Logger(LoginAttemptCleanupService.name);

  constructor(private readonly loginAttemptService: LoginAttemptService) {}

  @Cron(CronExpression.EVERY_3_HOURS)
  async handleCleanup() {
    const result = await this.loginAttemptService.deleteOlderThan(0);
    console.log(`Удалено ${result.count} попыток авторизоваться`);

    if (result.count > 0) {
      this.logger.log(`Удалено ${result.count} попыток авторизоваться`);
    }
  }
}
