import { ClientType } from 'src/common/types/client-type.enum';

export interface AuthenticatedRequest extends Request {
  clientType?: ClientType;
}

// для работы с аутентифицированным пользователем
