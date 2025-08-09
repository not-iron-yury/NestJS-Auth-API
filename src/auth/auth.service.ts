import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import bcrypt from 'bcrypt';
import { RegisterDto } from 'src/auth/dto/register.dto';
import { UserDto } from 'src/auth/dto/user.dto';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class AuthService {
  constructor(private readonly prisma: PrismaService) {}

  async register(dto: RegisterDto) {
    const hash = await bcrypt.hash(dto.password, 10);

    try {
      // пытаемся создать нового пользователя в БД (с уникальным email)
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
      });

      // если всё прошло успешно

      return new UserDto(user);
    } catch (error) {
      if (
        error instanceof PrismaClientKnownRequestError &&
        error.code === 'P2002'
      ) {
        throw new ForbiddenException(
          'Пользователь с таким email уже существует',
        );
      }
      throw error;
    }
  }

  login() {
    return 'Login logic';
  }
}
