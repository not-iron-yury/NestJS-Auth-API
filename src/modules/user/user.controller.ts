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

  // только ADMIN
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  @Get('all')
  getAllUsers() {
    return this.userService.findAll();
  }

  // MANAGER и ADMIN
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.MANAGER, Role.ADMIN)
  @Get('manager')
  getManagerView() {
    return { message: 'Ты не такой как все, ты...' };
  }

  // любой аутентифицированный
  @UseGuards(JwtAuthGuard)
  @Get('me')
  getMyProfile(@CurrentUser() user: User) {
    return user; // глобальный интерсептор ClassSerializerInterceptor преобразует ответ, откинув лишние данные
  }
}
