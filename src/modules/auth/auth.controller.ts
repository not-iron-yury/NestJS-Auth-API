import { Body, Controller, Get, Post, Query, Req, Res } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Request, Response } from 'express';
import { AuthService } from 'src/modules/auth/auth.service';
import { LoginDto } from 'src/modules/auth/dto/login.dto';
import { RefreshDto } from 'src/modules/auth/dto/refresh.dto';
import { RegisterDto } from 'src/modules/auth/dto/register.dto';
import { RequestEmailVerificationDto } from 'src/modules/auth/dto/request-email-verification.dto';
import { RequestPasswordResetDto } from 'src/modules/auth/dto/request-password-reset.dto';
import { ResetPasswordDto } from 'src/modules/auth/dto/reset-password.dto';
import { EmailConfirmService } from 'src/modules/auth/email-confirm.service';
import { PasswordResetSevice } from 'src/modules/auth/password-reset.service';
import { setRefreshTokenCookie } from '../../utils/set-refresh-token-cookie';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly config: ConfigService,
    private readonly emailConfirmService: EmailConfirmService,
    private readonly passwordResetSevice: PasswordResetSevice,
  ) {}

  @Get('ping')
  ping() {
    return 'pong';
  }

  @Post('register')
  async register(
    @Body() dto: RegisterDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const meta = { ip: req.ip, deviceInfo: req.headers['user-agent'] };
    const { user, tokens } = await this.authService.register(
      dto.password,
      dto.email,
      meta,
    );
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
    const { user, tokens } = await this.authService.login(
      dto.email,
      dto.password,
      meta,
    );
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

  // валидация ссылки подтверждения (в письме) и активация нового пользователя в случае успеха
  @Get('confirm-email')
  async confirmEmail(@Query('token') token: string) {
    return this.emailConfirmService.confirmEmail(token);
  }

  // запрос ссылки для подтверждения email
  @Post('email-verification')
  async sendVerification(
    @Body() dto: RequestEmailVerificationDto, // валидация на email, что б не делать лишние запросы к БД
    @Req() req: Request,
  ) {
    const meta = { ip: req.ip, deviceInfo: req.headers['user-agent'] };
    const res = await this.emailConfirmService.sendEmailVerifikation(
      dto.email,
      meta,
    );
    return {
      message: res.message,
      info: res.link || 'В повторном подтверждении нет нобходимости',
    };
  }

  // запрос на смену пароля
  @Post('request-password-reset')
  async requestPasswordReset(
    @Body() dto: RequestPasswordResetDto,
    @Req() req: Request,
  ) {
    const meta = { ip: req.ip, deviceInfo: req.headers['user-agent'] };
    return await this.passwordResetSevice.requestPasswordReset(dto.email, meta);
  }

  // валидация ссылки подтверждения (в письме) - опционально, сделано для фронта (показывать форму если valid:true )
  @Get('verify-password-reset')
  async verifyResetToken(@Query('token') token: string) {
    return await this.passwordResetSevice.verifyResetToken(token);
  }

  // смена пароля (отправка нового пароля)
  @Post('reset-password')
  async resetPassword(@Body() dto: ResetPasswordDto, @Req() req: Request) {
    const meta = { ip: req.ip, deviceInfo: req.headers['user-agent'] };
    return this.passwordResetSevice.resetePassword(
      dto.token,
      dto.newPassword,
      meta,
    );
  }
}
