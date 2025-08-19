import { Body, Controller, Post, Req, Res, UseGuards } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Request, Response } from 'express';
import { CurrentUser } from 'src/decorators/current-user.decorator';
import { AuthService } from 'src/modules/auth/auth.service';
import { LoginDto } from 'src/modules/auth/dto/login.dto';
import { RefreshDto } from 'src/modules/auth/dto/refresh.dto';
import { RegisterDto } from 'src/modules/auth/dto/register.dto';
import { JwtAuthGuard } from 'src/modules/auth/guards/jwt.guard';
import { setRefreshTokenCookie } from '../../utils/set-refresh-token-cookie';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly config: ConfigService,
  ) {}

  @Post('register')
  async register(
    @Body() dto: RegisterDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const meta = { ip: req.ip, deviceInfo: req.headers['user-agent'] };
    const { user, tokens } = await this.authService.register(dto, meta);
    setRefreshTokenCookie(res, tokens.refreshToken); // refresh_token через куку
    return { user, access_token: tokens.accessToken };
  }

  @Post('login')
  async login(
    @Body() dto: LoginDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const meta = { ip: req.ip, deviceInfo: req.headers['user-agent'] };
    const { user, tokens } = await this.authService.login(dto, meta);
    setRefreshTokenCookie(res, tokens.refreshToken); // refresh_token через куку
    return { user, access_token: tokens.accessToken };
  }

  @Post('refresh')
  async refresh(
    @Body() dto: RefreshDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    // passthrough: true - позволяет передавать HTTP-заголовки, куки
    // и статус-коды непосредственно клиенту без дополнительной обработки промежуточными слоями
  ) {
    // получаем refresh токен из тела запроса или cookies
    const refreshToken =
      dto.refreshToken || (req.cookies?.refresh_token as string);

    // revok старого refresh и получение новой пары
    const meta = { ip: req.ip, deviceInfo: req.headers['user-agent'] };
    const { tokens } = await this.authService.refresh(refreshToken, meta);
    setRefreshTokenCookie(res, tokens.refreshToken); // готовим cookie для res
    return { access_token: tokens.accessToken }; // refresh_token передаем через куку
  }

  @Post('logout')
  async logout(
    @Body() dto: RefreshDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const refreshToken =
      dto.refreshToken || (req.cookies?.refresh_token as string);

    await this.authService.revok(refreshToken); // revok refresh токена
    res.clearCookie('refresh_token');
    return { message: 'Logout done' };
  }

  // для тестирования
  @UseGuards(JwtAuthGuard)
  @Post('email-verification')
  async sendVerification(
    @CurrentUser('id') userId: number,
    @Req() req: Request,
  ) {
    const meta = { ip: req.ip, deviceInfo: req.headers['user-agent'] };
    const res = await this.authService.sendEmailVerifikation(userId, meta);
    return { message: 'Verification email sent', info: res.link };
  }
}
