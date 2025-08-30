import { ClientType } from 'src/common/types/client-type.types';

// декларация глобального пространства для библиотеки Express
declare module 'express-serve-static-core' {
  interface Request {
    clientType?: ClientType; // добавляем свойство clientType к оригинальному интерфейсу Request
  }
}

// Меняем глобальное определение самого интерфейса Request. Теперь любое обращение к Request включает поле clientType.
