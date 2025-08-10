import { createParamDecorator, ExecutionContext } from '@nestjs/common';

const factory = (data: keyof any, ctx: ExecutionContext) => {
  const request = ctx.switchToHttp().getRequest();
  const user = request.user;

  return data ? user?.[data] : user;
};

export const CurrentUser = createParamDecorator(factory);
