/*
  Warnings:

  - You are about to drop the column `email` on the `login_attempts` table. All the data in the column will be lost.
  - Added the required column `type` to the `login_attempts` table without a default value. This is not possible if the table is not empty.

*/
-- CreateEnum
CREATE TYPE "public"."AuthType" AS ENUM ('EMAIL', 'PHONE', 'OAUTH');

-- DropIndex
DROP INDEX "public"."login_attempts_email_createdAt_idx";

-- AlterTable
ALTER TABLE "public"."login_attempts" DROP COLUMN "email",
ADD COLUMN     "identifier" TEXT,
ADD COLUMN     "type" "public"."AuthType" NOT NULL;

-- DropEnum
DROP TYPE "public"."IdentityType";

-- CreateIndex
CREATE INDEX "login_attempts_identifier_createdAt_idx" ON "public"."login_attempts"("identifier", "createdAt");
