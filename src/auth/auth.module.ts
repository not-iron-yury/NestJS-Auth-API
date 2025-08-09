import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { PrismaModule } from 'src/prisma/prisma.module';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';

@Module({
  imports: [
    PassportModule,

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
  ],
  controllers: [AuthController],
  providers: [AuthService, PrismaService],
})
export class AuthModule {}
