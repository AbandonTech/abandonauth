/*
  Warnings:

  - A unique constraint covering the columns `[developer_application_id,uri]` on the table `CallbackUri` will be added. If there are existing duplicate values, this will fail.
  - A unique constraint covering the columns `[id,username]` on the table `User` will be added. If there are existing duplicate values, this will fail.

*/
-- CreateTable
CREATE TABLE "TestUser" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "username" TEXT NOT NULL,
    "password" TEXT NOT NULL,
    "refresh_token" TEXT NOT NULL,

    CONSTRAINT "TestUser_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "User_id_username_key" ON "User"("id", "username");

-- AddForeignKey
ALTER TABLE "TestUser" ADD CONSTRAINT "TestUser_id_username_fkey" FOREIGN KEY ("id", "username") REFERENCES "User"("id", "username") ON DELETE CASCADE ON UPDATE CASCADE;
