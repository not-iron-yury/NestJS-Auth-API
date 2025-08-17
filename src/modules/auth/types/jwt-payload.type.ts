import { Role as PrismaRole } from '@prisma/client';

export type JwtPayload = {
  sub: number;
  email: string;
  role: PrismaRole; // Prisma-тип
};
