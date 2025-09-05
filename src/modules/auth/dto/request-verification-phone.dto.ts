import { IsPhoneNumber } from 'class-validator';

export class RequestPhoneVerificationDto {
  @IsPhoneNumber('RU')
  phone: string;
}
