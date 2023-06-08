/*
  Warnings:

  - You are about to drop the `DeveloperAccount` table. If the table is not empty, all the data it contains will be lost.

*/
-- DropForeignKey
ALTER TABLE "DeveloperAccount" DROP CONSTRAINT "DeveloperAccount_owner_id_fkey";

-- DropTable
DROP TABLE "DeveloperAccount";

-- CreateTable
CREATE TABLE "DeveloperApplication" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "owner_id" UUID NOT NULL,

    CONSTRAINT "DeveloperApplication_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "DeveloperApplication_owner_id_key" ON "DeveloperApplication"("owner_id");

-- AddForeignKey
ALTER TABLE "DeveloperApplication" ADD CONSTRAINT "DeveloperApplication_owner_id_fkey" FOREIGN KEY ("owner_id") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
