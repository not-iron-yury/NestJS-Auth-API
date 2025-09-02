-- CreateEnum
CREATE TYPE "public"."IdentityType" AS ENUM ('EMAIL', 'PHONE', 'OAUTH');

-- CreateTable
CREATE TABLE "public"."identities" (
    "id" SERIAL NOT NULL,
    "userId" INTEGER NOT NULL,
    "type" "public"."IdentityType" NOT NULL,
    "value" TEXT NOT NULL,
    "verified" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "identities_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "identities_userId_idx" ON "public"."identities"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "identities_type_value_key" ON "public"."identities"("type", "value");

-- AddForeignKey
ALTER TABLE "public"."identities" ADD CONSTRAINT "identities_userId_fkey" FOREIGN KEY ("userId") REFERENCES "public"."User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
