import { Exclude } from 'class-transformer';

export class UserDto {
  id: number;
  email: string;
  createdAt: Date;
  updatedAt: Date;

  @Exclude() // гарантирует, что данное поле не будет сериализовано при преобразовании объекта в JSON (или другое представление)
  hash: string;

  constructor(partial: Partial<UserDto>) {
    Object.assign(this, partial);
  }
}
