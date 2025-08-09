import { Body, Controller, Post } from '@nestjs/common';
import { RegisterDto } from 'src/auth/dto/register.dto';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  register(@Body() dto: RegisterDto) {
    return this.authService.register(dto);
  }

  @Post('login')
  login() {
    return 'Login endpoint';
  }
}
