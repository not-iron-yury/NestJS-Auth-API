import { IsPhoneNumber } from 'class-validator';

export class RequestPasswordResetByPhoneDto {
  @IsPhoneNumber('RU')
  phone: string;
}
