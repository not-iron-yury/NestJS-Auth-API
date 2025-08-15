import { ClassSerializerInterceptor, ValidationPipe } from '@nestjs/common';
import { NestFactory, Reflector } from '@nestjs/core';
import cookieParser from 'cookie-parser';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule); // создаем приложение
  app.useGlobalPipes(new ValidationPipe({ whitelist: true })); // добавляем глобальную проверку валидности входящих данных (ко всему приложению)
  app.useGlobalInterceptors(new ClassSerializerInterceptor(app.get(Reflector))); // глабальная установка interceptors, для обработки исходящих данных (например, объект UserDto)
  app.use(cookieParser());
  await app.listen(process.env.PORT ?? 3000); // слушаем запросы на определенном порту
}
bootstrap(); // запускаем процедуру старта

/*
whitelist: true

При включенном режиме whitelist, любые поля входящего объекта, которые отсутствуют в схеме проверки
(например, указаных в декораторе класса), будут автоматически удалены перед обработкой контроллером.

Допустим, клиент отправляет POST-запрос с дополнительным полем adminRole, которого нет в классе CreateUserDto.
Если установлен флаг whitelist: true, поле adminRole будет проигнорировано и удалено до обработки запроса контроллером.

Это защищает приложение от возможных атак, связанных с передачей нежелательных полей,
и предотвращает занесение ненужных данных в базу данных или бизнес-логику приложения.
*/
