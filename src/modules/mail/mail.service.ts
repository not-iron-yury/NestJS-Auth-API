import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class MailService {
  private readonly logger = new Logger(MailService.name);
  constructor(private readonly config: ConfigService) {} // сейчас не нужен, но в будщем пригодится

  /**
   * Эмулирует отправку письма с ссылкой подтверждения.
   * Потом можно будет заменить реализацию на реальную (Nodemailer, SendGrid и т.п.)
   */
  sendVerificationEmail(
    email: string,
    link?: string,
    meta?: { ip?: string; deviceInfo?: string },
  ) {
    this.logger.log(`Send verification email to ${email}`);
    this.logger.log(`Verification link: ${link}`);

    if (meta?.ip) {
      this.logger.log(
        `IP: ${meta.ip} — device: ${meta.deviceInfo ?? 'unknown'}`,
      );
    }

    return { email, link }; // возвр. адрес и ссылку
  }
}
