import {
  IsOptional,
  IsPhoneNumber,
  IsString,
  IsUUID,
  MinLength,
} from 'class-validator';

export class LoginByPhoneDto {
  @IsPhoneNumber('RU', { message: 'Не валидный номер телефона для RU региона' })
  phone!: string;

  @IsString()
  @MinLength(6)
  password: string;

  @IsOptional()
  @IsUUID()
  deviceId?: string;
}
