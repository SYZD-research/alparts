CREATE TABLE "attachment_upload_chunks" (
	"upload_id" uuid NOT NULL,
	"chunk_index" integer NOT NULL,
	"size_bytes" integer NOT NULL,
	"storage_key" text NOT NULL,
	"etag" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "attachment_upload_chunks_upload_id_chunk_index_pk" PRIMARY KEY("upload_id","chunk_index"),
	CONSTRAINT "attachment_upload_chunks_storage_key_unique" UNIQUE("storage_key")
);
--> statement-breakpoint
ALTER TABLE "attachments" ADD COLUMN "chunk_count" integer DEFAULT 1 NOT NULL;--> statement-breakpoint
ALTER TABLE "attachments" ADD COLUMN "crypto_manifest" jsonb DEFAULT '{"version":0}'::jsonb NOT NULL;--> statement-breakpoint
ALTER TABLE "attachment_upload_chunks" ADD CONSTRAINT "attachment_upload_chunks_upload_id_attachment_uploads_id_fk" FOREIGN KEY ("upload_id") REFERENCES "public"."attachment_uploads"("id") ON DELETE cascade ON UPDATE no action;