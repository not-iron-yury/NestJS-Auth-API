import {
  Body,
  Controller,
  Get,
  Headers,
  Post,
  Query,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Request, Response } from 'express';
import { ClientTypeGuard } from 'src/common/guards/client-type.guard';
import { ClientType } from 'src/common/types/client-type.enum';
import { CurrentUser } from 'src/decorators/current-user.decorator';
import { AuthService } from 'src/modules/auth/auth.service';
import { EmailConfirmService } from 'src/modules/auth/confirm-email.service';
import { PhoneConfirmService } from 'src/modules/auth/confirm-phone.service';
import { ConfirmPhoneDto } from 'src/modules/auth/dto/confirm-phone.dto';
import { LoginByEmailDto } from 'src/modules/auth/dto/login-by-email.dto';
import { LoginByPhoneDto } from 'src/modules/auth/dto/login-by-phone.dto';
import { LogoutDto } from 'src/modules/auth/dto/logout.dto';
import { RefreshDto } from 'src/modules/auth/dto/refresh.dto';
import { RegisterByEmailDto } from 'src/modules/auth/dto/register-by-email.dto';
import { RegisterByPhoneDto } from 'src/modules/auth/dto/register-by-phone.dto';
import { RequestPasswordResetByEmailDto } from 'src/modules/auth/dto/request-password-reset-by-email.dto';
import { RequestPasswordResetByPhoneDto } from 'src/modules/auth/dto/request-password-reset-by-phone.dto';
import { RequestEmailVerificationDto } from 'src/modules/auth/dto/request-verification-email.dto';
import { RequestPhoneVerificationDto } from 'src/modules/auth/dto/request-verification-phone.dto';
import { ResetPasswordDto } from 'src/modules/auth/dto/reset-password.dto';
import { JwtAuthGuard } from 'src/modules/auth/guards/jwt.guard';
import { PasswordResetSevice } from 'src/modules/auth/password-reset.service';
import { setRefreshTokenCookie } from '../../utils/set-refresh-token-cookie';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly config: ConfigService,
    private readonly emailConfirmService: EmailConfirmService,
    private readonly phoneConfirmService: PhoneConfirmService,
    private readonly passwordResetSevice: PasswordResetSevice,
  ) {}

  @Get('ping')
  ping(@Res() res: Response) {
    res.status(200).json({ message: 'pong' });
  }

  @Post('register/email')
  @UseGuards(ClientTypeGuard)
  async registerByEmail(
    @Body() dto: RegisterByEmailDto,
    @Headers('x-client-type') clientType: ClientType,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const meta = { ip: req.ip, deviceInfo: req.headers['user-agent'] };

    const { user, tokens, deviceId } = await this.authService.registerByEmail(
      dto.email,
      dto.password,
      dto.deviceId, // если на клиенте сохранен id от прошлой сессии
      clientType,
      meta,
    );

    if (clientType === ClientType.WEB) {
      setRefreshTokenCookie(res, tokens.refreshToken); // refresh_token через куку, если web
      return { user, access_token: tokens.accessToken, deviceId };
    } else {
      return { user, tokens, deviceId };
    }
  }

  @Post('register/phone')
  @UseGuards(ClientTypeGuard)
  async registerByPhone(
    @Body() dto: RegisterByPhoneDto,
    @Headers('x-client-type') clientType: ClientType,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const meta = { ip: req.ip, deviceInfo: req.headers['user-agent'] };

    const { user, tokens, deviceId } = await this.authService.registerByPhone(
      dto.phone,
      dto.password,
      dto.deviceId, // если на клиенте сохранен id от прошлой сессии
      clientType,
      meta,
    );

    if (clientType === ClientType.WEB) {
      setRefreshTokenCookie(res, tokens.refreshToken); // refresh_token через куку, если web
      return { user, access_token: tokens.accessToken, deviceId };
    } else {
      return { user, tokens, deviceId };
    }
  }

  @Post('login/email')
  @UseGuards(ClientTypeGuard)
  async loginByEmail(
    @Body() dto: LoginByEmailDto,
    @Headers('x-client-type') clientType: ClientType,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const meta = { ip: req.ip, deviceInfo: req.headers['user-agent'] };

    const { user, tokens, deviceId } = await this.authService.loginByEmail(
      dto.email,
      dto.password,
      dto.deviceId, // если на клиенте сохранен id от прошлой сессии
      clientType,
      meta,
    );

    if (clientType === ClientType.WEB) {
      setRefreshTokenCookie(res, tokens.refreshToken); // refresh_token через куку, если web
      return { user, access_token: tokens.accessToken, deviceId };
    } else {
      return { user, tokens, deviceId };
    }
  }

  @Post('login/phone')
  @UseGuards(ClientTypeGuard)
  async loginByPhone(
    @Body() dto: LoginByPhoneDto,
    @Headers('x-client-type') clientType: ClientType,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const meta = { ip: req.ip, deviceInfo: req.headers['user-agent'] };

    const { user, tokens, deviceId } = await this.authService.loginByPhone(
      dto.phone,
      dto.password,
      dto.deviceId, // если на клиенте сохранен id от прошлой сессии
      clientType,
      meta,
    );

    if (clientType === ClientType.WEB) {
      setRefreshTokenCookie(res, tokens.refreshToken); // refresh_token через куку, если web
      return { user, access_token: tokens.accessToken, deviceId };
    } else {
      return { user, tokens, deviceId };
    }
  }

  @Post('refresh')
  @UseGuards(ClientTypeGuard)
  async refresh(
    @Body() dto: RefreshDto,
    @Headers('x-client-type') clientType: ClientType,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    // passthrough: true - позволяет передавать cookies клиенту без дополнительной обработки
  ) {
    const refreshToken =
      dto.refreshToken || (req.cookies?.refresh_token as string); // получаем refresh токен из тела запроса или cookies
    const meta = { ip: req.ip, deviceInfo: req.headers['user-agent'] };

    const { tokens } = await this.authService.refresh(
      refreshToken,
      clientType,
      meta,
    ); // revok старого refresh и получение новой пары

    if (clientType === ClientType.WEB) {
      setRefreshTokenCookie(res, tokens.refreshToken); // refresh_token передаем через куку, если web
      return { access_token: tokens.accessToken };
    } else {
      return {
        access_token: tokens.accessToken,
        refresh_token: tokens.refreshToken,
      };
    }
  }

  @Post('logout')
  @UseGuards(JwtAuthGuard)
  async logout(
    @Body() dto: LogoutDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    await this.authService.revok(dto.deviceId); // отзыв всех токенов выданных устройству
    res.clearCookie('refresh_token'); // сносим refreshToken из куки
    return { message: 'Logout done' };
  }

  // список все активных сессий пользователя
  @Get('sessions')
  @UseGuards(JwtAuthGuard)
  async getSessions(@CurrentUser('id') userId: number) {
    return this.authService.getSessions(userId); // возвр. массив объектов описывающих сессии
  }

  // валидация ссылки и активация нового пользователя (в случае успеха)
  @Get('confirm-email')
  async confirmEmail(@Query('token') token: string) {
    return this.emailConfirmService.confirmEmail(token);
  }

  // для повторного запроса ссылки для подтверждения email
  @Post('email-verification')
  async sendEmailVerification(
    @Body() dto: RequestEmailVerificationDto,
    @Req() req: Request,
  ) {
    const meta = { ip: req.ip, deviceInfo: req.headers['user-agent'] };
    // провека пользователя, генерация ссылки и отправка на email
    const res = await this.emailConfirmService.sendEmailVerification(
      dto.email,
      meta,
    );
    return {
      message: res.message,
      info: res.link || 'В повторном подтверждении нет нобходимости',
    };
  }

  // валидация SMS-кода и активация нового пользователя (в случае успеха)
  @Post('confirm-phone')
  async confirmPhone(@Body() dto: ConfirmPhoneDto) {
    return this.phoneConfirmService.confirmPhone(dto.userId, dto.code);
  }

  // для повторного запроса SMS-кода для подтверждения номера телефона
  @Post('phone-verification')
  async sendPhoneVerifikation(
    @Body() dto: RequestPhoneVerificationDto,
    @Req() req: Request,
  ) {
    const meta = { ip: req.ip, deviceInfo: req.headers['user-agent'] };
    // провека пользователя, генерация и отправка SMS
    const res = await this.phoneConfirmService.sendPhoneVerifikation(
      dto.phone,
      meta,
    );
    return {
      message: res.message,
      info: res.code || 'В повторном подтверждении нет нобходимости',
    };
  }

  // запрос на смену пароля по email (инициализация процесса замены пароля) - шаг 1
  @Post('request-password-reset/email')
  async RequestPasswordResetByEmail(
    @Body() dto: RequestPasswordResetByEmailDto,
    @Headers('x-client-type') clientType: ClientType,
    @Req() req: Request,
  ) {
    const meta = { ip: req.ip, deviceInfo: req.headers['user-agent'] };
    return await this.passwordResetSevice.RequestPasswordResetByEmail(
      dto.email,
      clientType,
      meta,
    );
  }

  // запрос на смену пароля по phone (инициализация процесса замены пароля)
  @Post('request-password-reset/phone')
  async RequestPasswordResetByPhone(
    @Body() dto: RequestPasswordResetByPhoneDto,
    @Headers('x-client-type') clientType: ClientType,
    @Req() req: Request,
  ) {
    const meta = { ip: req.ip, deviceInfo: req.headers['user-agent'] };
    return await this.passwordResetSevice.RequestPasswordResetByPhone(
      dto.phone,
      clientType,
      meta,
    );
  }

  // валидация passwordResetToken: опционально для web, сделано для фронта (показывать форму если valid:true ) - шаг 1-1
  @Get('verify-password-reset')
  async verifyResetToken(
    @Query('token') token: string,
  ): Promise<{ valid: true }> {
    return await this.passwordResetSevice.verifyResetToken(token);
  }

  // передача токена для замены пароля и отправка нового пароля  - шаг 2
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
