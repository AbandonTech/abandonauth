/*
  Warnings:

  - Added the required column `uri` to the `CallbackUri` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "CallbackUri" ADD COLUMN     "uri" TEXT NOT NULL;
