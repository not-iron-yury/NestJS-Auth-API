import { IsEnum, IsNotEmpty, IsString, Validate } from 'class-validator';
import { ClientType } from 'src/common/types/client-type.enum';
import { IsIdentityValueValid } from '../validators/is-identity-value.validator';

export class IdentityDto {
  @IsEnum(ClientType) // проверка на соотвествие одному из значений в enum ClientType
  type!: ClientType;

  @IsString()
  @IsNotEmpty()
  @Validate(IsIdentityValueValid) // используем кастомный валидатор
  value!: string;
}
