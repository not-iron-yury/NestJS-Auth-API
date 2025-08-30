import {
  BadRequestException,
  CanActivate,
  ExecutionContext,
  Injectable,
} from '@nestjs/common';
import { Request } from 'express'; // обязательно используем Request, котрый был расширен в 'src/types/index.d.ts
import { ClientType } from 'src/common/types/client-type.enum';

@Injectable()
// ClientTypeGuard достаёт и валидирует x-client-type, а затем кладёт в request.clientType
export class ClientTypeGuard implements CanActivate {
  // Метод canActivate должен возвращать булево значение (true или false),
  // разрешая (или нет) переход дальше в обработчик маршрута или контроллер.
  canActivate(context: ExecutionContext): boolean {
    const request = context
      .switchToHttp() // context содержит всю необходимую информацию о текущем запросе (больше, чем нам нужно)
      .getRequest<Request>(); // получаем экземпляр текущего HTTP-запроса из контекста, урезая его до типа Request из Express

    // извлекается заголовок "x-client-type"
    const clientType = request.headers['x-client-type'] as ClientType;

    // проверочка
    if (!clientType || !Object.values(ClientType).includes(clientType)) {
      throw new BadRequestException('Не передан тип клиента');
    }

    // добавляем новое свойство clientType в объект запроса и кладем в него соответствующее значение
    request.clientType = clientType;

    return true;
  }
}
