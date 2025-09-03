import { Role } from '@prisma/client';
import { Exclude } from 'class-transformer';

export class UserDto {
  id: number;
  email?: string | null;
  phone?: string | null;
  role: Role;
  isActive: boolean;

  @Exclude() // гарантирует, что данное поле не будет сериализовано при преобразовании объекта в JSON (или другое представление)
  hash: string;

  @Exclude()
  createdAt: Date;

  @Exclude()
  updatedAt: Date;

  @Exclude()
  lockedUntil: null | Date;

  constructor(partial: Partial<UserDto>) {
    Object.assign(this, partial);
  }
}
