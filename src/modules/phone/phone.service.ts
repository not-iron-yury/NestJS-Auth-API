import { Injectable, Logger } from '@nestjs/common';

@Injectable()
export class PhoneService {
  private readonly logger = new Logger(PhoneService.name);

  // Эмулирует отправку SMS-кода для подтверждения номера телефона. В проде можно будет заменить на реальную реализацию.
  sendVerificationSMS(phone: string, code: string) {
    this.logger.log(`Send verification sms to ${phone}`);
    this.logger.log(`Verification sms: ${code}`);

    return { phone, code }; // возврат для тестов
  }

  // Эмулирует отправку SMS-кода для сброса пароля. Отдельный метод на случай разного текста в SMS-сообщении с кодом.
  sendPasswordResetPhone(phone: string, code: string) {
    this.logger.log(`Send reset sms to ${phone}`);
    this.logger.log(`Verification sms: ${code}`);

    return { phone, code }; // возврат для тестов
  }
}
