/*
  Warnings:

  - Made the column `clientType` on table `refresh_tokens` required. This step will fail if there are existing NULL values in that column.

*/
-- AlterTable
ALTER TABLE "public"."refresh_tokens" ALTER COLUMN "clientType" SET NOT NULL;
