---
name: Email Reader
description: Read and search email messages from your IMAP mailbox
mcp_server_url: https://your-domain.com/mcp
oauth_scopes:
  - mail:folders
  - mail:read
  - mail:search
---

# Email Reader

This skill connects to your email account via the IMAP Bridge and allows you to:

- **List folders** in your mailbox
- **List messages** in any folder with pagination
- **Read full messages** including headers and body
- **Search messages** by sender, date, subject, or body text

## Setup

1. Deploy the IMAP Bridge server (see README)
2. Visit your bridge URL and log in
3. Add your email account (IMAP credentials)
4. In Claude.ai, go to Settings > Integrations > Add Custom Connector
5. Enter your bridge URL: `https://your-domain.com/mcp`
6. Authorize with your bridge account and select "Email Reader" permissions

## Available Tools

### list_folders
Lists all mailbox folders. No arguments needed.

### list_messages
- `folder` (optional): Folder path, defaults to "INBOX"
- `page` (optional): Page number, defaults to 1
- `pageSize` (optional): Messages per page, defaults to 20

### read_message
- `folder` (optional): Folder path, defaults to "INBOX"
- `uid` (required): Message UID from list_messages

### search_messages
- `query` (optional): Search text
- `from` (optional): Filter by sender
- `to` (optional): Filter by recipient
- `since` (optional): Date filter (YYYY-MM-DD)
- `before` (optional): Date filter (YYYY-MM-DD)
- `unseen` (optional): Only unread messages
- `limit` (optional): Max results
