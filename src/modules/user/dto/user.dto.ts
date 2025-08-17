import { Role as PrismaRole } from '@prisma/client';
import { Exclude } from 'class-transformer';

export class UserDto {
  id: number;
  email: string;
  role: PrismaRole; // Prisma-тип

  @Exclude() // гарантирует, что данное поле не будет сериализовано при преобразовании объекта в JSON (или другое представление)
  hash: string;

  @Exclude()
  createdAt: Date;

  @Exclude()
  updatedAt: Date;

  constructor(partial: Partial<UserDto>) {
    Object.assign(this, partial);
  }
}
