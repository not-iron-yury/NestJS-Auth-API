/*
  Warnings:

  - Added the required column `clientType` to the `password_reset_tokens` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "public"."password_reset_tokens" ADD COLUMN     "clientType" TEXT NOT NULL;
