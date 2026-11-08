CREATE TABLE `audit_events` (
	`id` text PRIMARY KEY NOT NULL,
	`ts` text NOT NULL,
	`request_id` text NOT NULL,
	`client_id` text,
	`mailbox_id` text,
	`folder` text,
	`uid_validity` integer,
	`uid` integer,
	`uids` text,
	`uids_truncated` integer DEFAULT 0 NOT NULL,
	`tool` text NOT NULL,
	`outcome` text NOT NULL,
	`error_code` text,
	`cached` integer DEFAULT 0 NOT NULL,
	`reconciled` integer DEFAULT 0 NOT NULL,
	`duration_ms` integer,
	CONSTRAINT "audit_events_outcome" CHECK("audit_events"."outcome" IN ('ok','denied','failed','unknown_outcome'))
);
--> statement-breakpoint
CREATE INDEX `audit_ts` ON `audit_events` (`ts`);--> statement-breakpoint
CREATE INDEX `audit_client` ON `audit_events` (`client_id`,`ts`);--> statement-breakpoint
ALTER TABLE `mailboxes` ADD `status` text DEFAULT 'unknown' NOT NULL;--> statement-breakpoint
ALTER TABLE `mailboxes` ADD `last_error_code` text;--> statement-breakpoint
ALTER TABLE `mailboxes` ADD `last_ok_at` text;--> statement-breakpoint
ALTER TABLE `mailboxes` ADD `next_retry_at` text;