import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { UserDto } from 'src/auth/dto/user.dto';
import { type JwtPayload } from 'src/auth/types/jwt-payload.type';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private readonly config: ConfigService, // DI Config
    private readonly prisma: PrismaService, // DI Prisma
  ) {
    // Конструктор PassportStrategy настраивает основные параметры поведения стратегии аутентификации,
    // обеспечивая безопасность и удобство разработки REST API приложений с использованием NestJS и Passport.js.
    super({
      // Настройка механизма извлечения JWT
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(), // автоматическое получение JWT-токенов из заголовка HTTP-запросов
      // Установка флага истечения срока жизни токена
      ignoreExpiration: false, // система должна проверять срок действия токена и отклонять истекшие токены
      // Защита ключа шифрования
      secretOrKey: config.get<string>('JWT_SECRET') as string, // параметр secretOrKey используется для расшифровки подписанных JWT-токенов, защищая приложение от подделывания токенов злоумышленниками
    });
  }

  // проверка существования пользователя
  async validate(payload: JwtPayload) {
    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub },
    });
    if (!user) {
      throw new UnauthorizedException('Пользователь не найден');
    }

    // возвращаем объект, который попадёт в request.user
    return new UserDto(user);
  }
}
