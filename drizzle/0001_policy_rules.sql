CREATE TABLE `policy_rules` (
	`id` text PRIMARY KEY NOT NULL,
	`client_id` text NOT NULL,
	`mailbox_id` text NOT NULL,
	`folder` text NOT NULL,
	`operation` text NOT NULL,
	`effect` text NOT NULL,
	`created_at` text DEFAULT (datetime('now')) NOT NULL,
	FOREIGN KEY (`client_id`) REFERENCES `oauth_clients`(`client_id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`mailbox_id`) REFERENCES `mailboxes`(`id`) ON UPDATE no action ON DELETE cascade,
	CONSTRAINT "policy_rules_operation" CHECK("policy_rules"."operation" IN ('search','read_headers','read_body','draft','move','flag')),
	CONSTRAINT "policy_rules_effect" CHECK("policy_rules"."effect" IN ('allow','deny'))
);
--> statement-breakpoint
CREATE INDEX `policy_rules_client_mailbox` ON `policy_rules` (`client_id`,`mailbox_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `policy_rules_unique` ON `policy_rules` (`client_id`,`mailbox_id`,`folder`,`operation`);--> statement-breakpoint
-- v0 -> v1 data migration (no widening): read => search/read_headers/read_body on '*'; draft => draft on '*';
-- organize => move/flag on '*'.
INSERT INTO `policy_rules` (`id`, `client_id`, `mailbox_id`, `folder`, `operation`, `effect`, `created_at`)
SELECT lower(hex(randomblob(16))), g.`client_id`, g.`mailbox_id`, '*', m.`operation`, 'allow', g.`created_at`
  FROM `grants` g
  JOIN (
    SELECT 'read' AS `capability`, 'search' AS `operation`
    UNION ALL SELECT 'read', 'read_headers'
    UNION ALL SELECT 'read', 'read_body'
    UNION ALL SELECT 'draft', 'draft'
    UNION ALL SELECT 'organize', 'move'
    UNION ALL SELECT 'organize', 'flag'
  ) m ON m.`capability` = g.`capability`;--> statement-breakpoint
DROP TABLE `grants`;