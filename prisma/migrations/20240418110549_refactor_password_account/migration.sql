/*
  Warnings:

  - You are about to drop the `TestUser` table. If the table is not empty, all the data it contains will be lost.

*/
-- DropForeignKey
ALTER TABLE "TestUser" DROP CONSTRAINT "TestUser_id_username_fkey";

-- DropTable
DROP TABLE "TestUser";

-- CreateTable
CREATE TABLE "PasswordAccount" (
    "id" BIGINT NOT NULL,
    "password" TEXT NOT NULL,
    "user_id" UUID NOT NULL,

    CONSTRAINT "PasswordAccount_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "PasswordAccount_user_id_key" ON "PasswordAccount"("user_id");

-- AddForeignKey
ALTER TABLE "PasswordAccount" ADD CONSTRAINT "PasswordAccount_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
