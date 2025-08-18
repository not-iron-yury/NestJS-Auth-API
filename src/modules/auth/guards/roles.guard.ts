import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Role } from '@prisma/client';
import { ROLES_KEY } from 'src/modules/auth/decorators/roles.decorator';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  // проверяет наличие требуемой роли у пользователя перед активацией маршрута
  // но запускается уже после JwtAuthGuard (который валидирует и получает из БД данные пользователя)
  canActivate(context: ExecutionContext): boolean {
    // получаем список всех требований по ролям, указанных в декораторах (@Roles())
    const requiredRoles = this.reflector.getAllAndOverride<Role[]>(ROLES_KEY, [
      context.getHandler(), // ищем роль на уровне метода контроллера
      context.getClass(), // ищем роль на уровне класса-контроллера
    ]);

    // если роли вообще не указаны — пропускаем проверку
    if (!requiredRoles || requiredRoles.length === 0) {
      return true;
    }

    // преобразуем контекст запроса в объект HttpRequest,
    const req = context.switchToHttp().getRequest();
    // чтобы получить доступ к объекту user из запроса (после аутентификации)
    const user = req.user;

    // если пользователь не найден — отказываем в доступе
    if (!user) {
      throw new UnauthorizedException('User not authenticated');
    }

    // роль текущего пользователя
    const userRole: Role | undefined = user.role;

    // если нет роли — отказываем в доступе
    if (!userRole) {
      throw new ForbiddenException('No role assigned to user');
    }

    // если роль пользователя "ниже" допустимыой — отказываем в доступе "недостаточно прав"
    const allowed = requiredRoles.includes(userRole);
    if (!allowed) {
      throw new ForbiddenException('Insufficient role');
    }

    // запрос успешно прошёл проверку, возвращаем разрешение
    return true;

    // ВАЖНО! До контроллера дойдут только те запросы, которые пропустили JwtAuthGuard и RolesGuard.
  }
}
