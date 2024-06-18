-- CreateTable
CREATE TABLE "CallbackUri" (
    "id" SERIAL NOT NULL,
    "developer_application_id" UUID NOT NULL,

    CONSTRAINT "CallbackUri_pkey" PRIMARY KEY ("id")
);

-- AddForeignKey
ALTER TABLE "CallbackUri" ADD CONSTRAINT "CallbackUri_developer_application_id_fkey" FOREIGN KEY ("developer_application_id") REFERENCES "DeveloperApplication"("id") ON DELETE CASCADE ON UPDATE CASCADE;
