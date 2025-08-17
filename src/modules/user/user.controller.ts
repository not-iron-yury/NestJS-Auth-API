import { Controller, Get, UseGuards } from '@nestjs/common';
import type { User } from '@prisma/client';
import { CurrentUser } from 'src/decorators/current-user.decorator';
import { JwtAuthGuard } from 'src/modules/auth/guards/jwt.guard';

@Controller('user')
export class UserController {
  @UseGuards(JwtAuthGuard)
  @Get('profile')
  getMyProfile(@CurrentUser() user: User) {
    return user; // глобальный интерсептор ClassSerializerInterceptor преобразует ответ, откинув лишние данные
  }

  @UseGuards(JwtAuthGuard)
  @Get('email')
  getMyEmail(@CurrentUser('email') email: string) {
    return { email };
  }
}
