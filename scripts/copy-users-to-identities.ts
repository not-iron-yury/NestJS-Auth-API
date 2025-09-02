import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function main() {
  // 1) находим всех существующих пользователей
  const users = await prisma.user.findMany();

  // 2) копируем данные каждого в таблицу identity
  for (const user of users) {
    await prisma.identity.create({
      data: {
        userId: user.id,
        type: 'EMAIL',
        value: user.email,
        verified: user.isActive,
      },
    });
  }

  console.log(`В таблицу Identity скопировано ${users.length} пользователей`);
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(() => {
    prisma.$disconnect().catch(() => {}); // подавляем лишние ошибки
  });

// запуск в bash
// npx ts-node scripts/copy-users-to-identities.ts
