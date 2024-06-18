/*
  Warnings:

  - A unique constraint covering the columns `[developer_application_id,uri]` on the table `CallbackUri` will be added. If there are existing duplicate values, this will fail.

*/
-- CreateIndex
CREATE UNIQUE INDEX "CallbackUri_developer_application_id_uri_key" ON "CallbackUri"("developer_application_id", "uri");
