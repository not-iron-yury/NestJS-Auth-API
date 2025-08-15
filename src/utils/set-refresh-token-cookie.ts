import { Response } from 'express';

export function setRefreshTokenCookie(res: Response, token: string) {
  // определяем имя

  // обновляем
  res.cookie('refresh_token', token, {
    httpOnly: true, // запрещающий доступ к этому cookie через JavaScript на стороне клиента (защита от XSS)
    secure: true, //  используется только через защищённые соединения (HTTPS)
    sameSite: 'strict', // ограничивает передачу cookie между доменами ('strict' - только собственный сайт может отправить запрос с данным cookie)
    path: '/', // путь, для которого действителен данный cookie.
    maxAge:
      (Number(process.env.REFRESH_TOKEN_EXPIRES_IN) || 7) * 24 * 60 * 60 * 1000, // срок годности куки
  });
}
