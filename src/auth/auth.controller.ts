import { Body, Controller, Get, Post, UseGuards } from '@nestjs/common';
import { type User } from '@prisma/client';
import { LoginDto } from 'src/auth/dto/login.dto';
import { RegisterDto } from 'src/auth/dto/register.dto';
import { JwtAuthGuard } from 'src/auth/guards/jwt.guard';
import { CurrentUser } from 'src/decorators/current-user.decorator';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  register(@Body() dto: RegisterDto) {
    return this.authService.register(dto);
  }

  @Post('login')
  login(@Body() dto: LoginDto) {
    return this.authService.login(dto);
  }

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
