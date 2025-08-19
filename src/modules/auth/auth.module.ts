import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { AuthController } from 'src/modules/auth/auth.controller';
import { AuthService } from 'src/modules/auth/auth.service';
import { RefreshTokenCleanupService } from 'src/modules/auth/refresh-token-cleanup.service';
import { JwtStrategy } from 'src/modules/auth/strategies/jwt.strategy';
import { PrismaModule } from '../../prisma/prisma.module';
import { MailModule } from 'src/modules/mail/mail.module';

@Module({
  imports: [
    PassportModule.register({ defaultStrategy: 'jwt' }),

    // Централизованное управлени конфигурационными параметрами (такими как ключи шифрования и сроки жизни токенов) -
    // уменьшает потребность в многократном обращении к среде выполнения (process.env) в различных частях приложения.
    // Aсинхронная регистрация (registerAsync) полезна, когда конфигурация должна загружаться динамически,
    // а не жестко закладываться в исходный код. Использование registerAsync(), делает систему аутентификации безопасной и гибкой.
    // Конфигурация тайминга и секретных ключей берётся из внешних источников, что позволяет легко менять параметры без перекомпиляции кода.
    JwtModule.registerAsync({
      imports: [ConfigModule], // Доступ к необходимым параметрам из внешней конфигурации.
      inject: [ConfigService], // Зависимости, которые должны быть внедрены в фабричную функцию. В данном случае это ConfigService, который позволяет обращаться к значениям переменных среды.

      // Фабричная функция, ответственная за возврат объекта конфигурации для JWT-модуля.
      // Внутри неё выполняется чтение необходимых данных (секретного ключа и сроков истечения токенов)
      // и передача их в виде готового объекта.
      useFactory: (config: ConfigService) => ({
        secret: config.get<string>('JWT_SECRET'),
        signOptions: {
          expiresIn: config.get<string>('JWT_EXPIRES_IN'),
        },
      }),
    }),
    PrismaModule,
    MailModule,
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy, RefreshTokenCleanupService],
})
export class AuthModule {}
