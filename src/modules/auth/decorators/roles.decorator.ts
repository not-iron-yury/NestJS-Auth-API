import { SetMetadata } from '@nestjs/common';
import type { Role } from '@prisma/client';

export const ROLES_KEY = 'roles';
export const Roles = (...roles: Role[]) => SetMetadata(ROLES_KEY, roles);

/*
1.
SetMetadata — это фабрика декораторов.

Roles(...) функция, которая сначала принимает аргументы (roles), а потом возвращает реальный декоратор,
который через Reflect.defineMetadata приклепляет метаданные.

SetMetadata(key, value) только прикрепляет данные к ВСЕМУ контроллеру или его отдельному методу.

@SetMetadata('roles', ['ADMIN'])    приклеит метаданные с ключом "roles" и значением ['ADMIN'].


2.
ROLES_KEY - константа, хранящая строку, чтобы не писать её руками в нескольких местах и не ошибиться.
Guard будет потом искать эти метаданные по этому ключу.


3. Прикрепить декоратор к выбранному методу контроллера следующим образом:

@Roles(Role.ADMIN, Role.MANAGER)

NestJS сохранит метаданные "roles": ["ADMIN", "MANAGER"] на этом методе контроллера.
*/
