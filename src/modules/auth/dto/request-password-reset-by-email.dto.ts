import { IsEmail } from 'class-validator';

export class RequestPasswordResetByEmailDto {
  @IsEmail()
  email: string;
}
