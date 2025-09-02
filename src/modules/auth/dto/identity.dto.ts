import { IdentityType } from '@prisma/client';
import { IsEnum, IsNotEmpty, IsString, Validate } from 'class-validator';
import { IsIdentityValueValid } from '../validators/is-identity-value.validator';

export class IdentityDto {
  @IsEnum(IdentityType) // проверка на соотвествие одному из значений в enum IdentityType
  type!: IdentityType;

  @IsString()
  @IsNotEmpty()
  @Validate(IsIdentityValueValid) // используем кастомный валидатор
  value!: string;
}
