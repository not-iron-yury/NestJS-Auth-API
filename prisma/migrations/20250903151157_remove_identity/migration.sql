/*
  Warnings:

  - You are about to drop the `identities` table. If the table is not empty, all the data it contains will be lost.

*/
-- DropForeignKey
ALTER TABLE "public"."identities" DROP CONSTRAINT "identities_userId_fkey";

-- DropTable
DROP TABLE "public"."identities";
