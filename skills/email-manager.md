---
name: Email Manager
description: Full email management - read, organize, and send emails
mcp_server_url: https://your-domain.com/mcp
oauth_scopes:
  - mail:folders
  - mail:read
  - mail:search
  - mail:modify
  - mail:send
---

# Email Manager

This skill provides full email management capabilities via the IMAP Bridge:

- **Read** emails and search your mailbox
- **Organize** by moving messages between folders and setting flags
- **Send** new emails or reply to existing ones

## Setup

1. Deploy the IMAP Bridge server (see README)
2. Visit your bridge URL and log in
3. Add your email account (IMAP + SMTP credentials)
4. In Claude.ai, go to Settings > Integrations > Add Custom Connector
5. Enter your bridge URL: `https://your-domain.com/mcp`
6. Authorize with all permissions

## Additional Tools (beyond Email Reader)

### move_message
- `folder` (required): Source folder path
- `uid` (required): Message UID
- `destination` (required): Target folder path

### flag_message
- `folder` (optional): Folder path
- `uid` (required): Message UID
- `seen` (optional): true=read, false=unread
- `flagged` (optional): true=star, false=unstar
- `deleted` (optional): Mark as deleted

### send_mail
- `to` (required): Recipient email(s)
- `subject` (required): Email subject
- `body` (required): Plain text body
- `cc` (optional): CC address(es)
- `inReplyTo` (optional): Message-ID for threading
- `html` (optional): HTML body
