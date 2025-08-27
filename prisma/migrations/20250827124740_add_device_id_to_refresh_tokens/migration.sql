/*
  Warnings:

  - Added the required column `deviceId` to the `refresh_tokens` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "public"."refresh_tokens" ADD COLUMN     "deviceId" UUID NOT NULL;

-- CreateIndex
CREATE INDEX "refresh_tokens_userId_deviceId_idx" ON "public"."refresh_tokens"("userId", "deviceId");
