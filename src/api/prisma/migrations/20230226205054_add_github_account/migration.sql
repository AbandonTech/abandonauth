-- DropIndex
DROP INDEX "User_username_key";

-- CreateTable
CREATE TABLE "GitHubAccount" (
    "id" INTEGER NOT NULL,
    "user_id" UUID NOT NULL,

    CONSTRAINT "GitHubAccount_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "GitHubAccount_user_id_key" ON "GitHubAccount"("user_id");

-- AddForeignKey
ALTER TABLE "GitHubAccount" ADD CONSTRAINT "GitHubAccount_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
