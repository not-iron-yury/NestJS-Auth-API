import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class MailService {
  private readonly logger = new Logger(MailService.name);
  private readonly fromAddress: string;
  private readonly fromName: string;

  constructor(private readonly config: ConfigService) {
    this.fromName = this.config.get<string>('MAIL_FROM_NAME') ?? 'Support';
    this.fromAddress =
      this.config.get<string>('MAIL_FROM') ?? 'no-reply@example.com';
  }

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
    this.logger.debug(`From: ${this.fromName} <${this.fromAddress}>`);
    this.logger.log(`Verification link: ${link}`);

    if (meta?.ip) {
      this.logger.log(
        `IP: ${meta.ip} — device: ${meta.deviceInfo ?? 'unknown'}`,
      );
    }

    return { email, link }; // возвр. адрес и ссылку
  }

  /**
   * Эмулирует отправку письма сброса пароля.
   * В проде нужно будет заменить реализацию (Nodemailer, SendGrid и т.п.)
   * Отдельный метод, чтобы в проде можно было отправлять другой шаблон письма.
   */
  sendPasswordResetEmail(
    email: string,
    link?: string,
    meta?: { ip?: string; deviceInfo?: string },
  ) {
    this.logger.log(`Send password reset email to ${email}`);
    this.logger.debug(`From: ${this.fromName} <${this.fromAddress}>`);
    this.logger.log(`Verification link: ${link}`);

    if (meta?.ip) {
      this.logger.log(
        `IP: ${meta.ip} — device: ${meta.deviceInfo ?? 'unknown'}`,
      );
    }

    return { email, link }; // возвр. адрес и ссылку
  }
}
