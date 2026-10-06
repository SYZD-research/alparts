-- A user with a passkey can turn off password login; an operator password
-- reset turns it back on.
ALTER TABLE "users" ADD COLUMN "password_login_disabled" boolean DEFAULT false NOT NULL;
