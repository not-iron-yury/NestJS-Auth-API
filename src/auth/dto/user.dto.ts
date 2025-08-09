import { Exclude } from 'class-transformer';

export class UserDto {
  id: number;
  email: string;

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
