import { AuthType } from '@prisma/client';
import {
  ValidationArguments,
  ValidatorConstraint,
  ValidatorConstraintInterface,
} from 'class-validator';

@ValidatorConstraint({ name: 'IsIdentityValueValid', async: false }) // регистрируем кастомный валидатор
export class IsIdentityValueValid implements ValidatorConstraintInterface {
  //
  // 1. Основной метод для проверки правильности введенных данных
  validate(_: any, args: ValidationArguments): boolean {
    // 1) получаем объект, содержащий передаваемые аргументы (тип и значение)
    const obj = args.object as any;

    // 2) извлекаем тип идентификации и само значение
    const type: AuthType = obj.type;
    const value: string = obj.value;

    // 3) проверочка наличия идентификатора
    if (!type || typeof value !== 'string') return false;

    // 4) валидация значения идентификатора (в зависимости от его типа)
    switch (type) {
      case AuthType.EMAIL:
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value.trim().toLowerCase()); // простая, но практичная проверка email
      case AuthType.PHONE:
        return /^\+?[1-9]\d{6,14}$/.test(value.trim()); // +{country}{number}, 7-15 цифр (простая проверка)
      case AuthType.OAUTH:
        return value.trim().length > 0; // для oauth значение может быть внешний id или email — просто проверяем непустую строку
      default:
        return false;
    }
  }

  // 2. Метод для вывода сообщений об ошибках при неправильных значениях
  defaultMessage(args: ValidationArguments): string {
    const obj = args.object as any;
    if (!obj || !obj.type) return 'IsIdentityValue: неправильный идентификатор';
    switch (obj.type) {
      case AuthType.EMAIL:
        return 'IsIdentityValue: некорректный адрес электронной почты';
      case AuthType.PHONE:
        return 'IsIdentityValue: некорректный номер телефона';
      default:
        return 'IsIdentityValue: некорректные идентификационные данные';
    }
  }
}
