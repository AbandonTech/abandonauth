-- AlterTable
CREATE SEQUENCE passwordaccount_id_seq;
ALTER TABLE "PasswordAccount" ALTER COLUMN "id" SET DEFAULT nextval('passwordaccount_id_seq');
ALTER SEQUENCE passwordaccount_id_seq OWNED BY "PasswordAccount"."id";
