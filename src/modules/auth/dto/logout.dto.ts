import { IsOptional, IsString, MinLength } from 'class-validator';

export class LogoutDto {
  @IsOptional()
  @IsString()
  @MinLength(1)
  refreshToken?: string;
}
