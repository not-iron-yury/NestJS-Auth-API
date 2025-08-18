import { Controller, Get, UseGuards } from '@nestjs/common';
import { Role, type User } from '@prisma/client';
import { CurrentUser } from 'src/decorators/current-user.decorator';
import { Roles } from 'src/modules/auth/decorators/roles.decorator';
import { JwtAuthGuard } from 'src/modules/auth/guards/jwt.guard';
import { RolesGuard } from 'src/modules/auth/guards/roles.guard';
import { UserService } from 'src/modules/user/user.service';

@Controller('user')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  getMyProfile(@CurrentUser() user: User) {
    return user; // глобальный интерсептор ClassSerializerInterceptor преобразует ответ, откинув лишние данные
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Get('all')
  @Roles(Role.ADMIN)
  getAllUsers() {
    return this.userService.findAll();
  }
}
