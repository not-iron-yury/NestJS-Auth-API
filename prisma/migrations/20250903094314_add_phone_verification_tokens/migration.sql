-- CreateTable
CREATE TABLE "public"."phone_verification_tokens" (
    "id" SERIAL NOT NULL,
    "userId" INTEGER NOT NULL,
    "token" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "used" BOOLEAN NOT NULL DEFAULT false,
    "createdByIp" TEXT,
    "deviceInfo" TEXT,

    CONSTRAINT "phone_verification_tokens_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "phone_verification_tokens_userId_token_key" ON "public"."phone_verification_tokens"("userId", "token");

-- AddForeignKey
ALTER TABLE "public"."phone_verification_tokens" ADD CONSTRAINT "phone_verification_tokens_userId_fkey" FOREIGN KEY ("userId") REFERENCES "public"."User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
