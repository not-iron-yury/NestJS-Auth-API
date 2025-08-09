import { Injectable } from '@nestjs/common';

@Injectable()
export class AuthService {
  register() {
    return 'Register logic';
  }

  login() {
    return 'Login logic';
  }
}
