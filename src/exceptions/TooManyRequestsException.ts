import { HttpException } from '@nestjs/common';

export class TooManyRequestsException extends HttpException {
  constructor(message = 'Too many requests') {
    super(message, 429);
  }
}
