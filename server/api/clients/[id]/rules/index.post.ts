import { defineEventHandler, getRouterParam, setResponseStatus } from "h3";
import type { Rule } from "../../../../../shared/types/api";
import { requireAdmin } from "../../../../utils/requireAdmin";
import { readJsonBody } from "../../../../utils/readJson";
import { apiError } from "../../../../utils/apiError";
import { getClientRow, trimmedString } from "../../../../utils/dto-common";
import { toRuleDto } from "../../../../utils/dto-client";
import { getDb } from "../../../../core/db/database.js";
import { getMailbox } from "../../../../core/imap/mailboxes.js";
import { isOperation, isValidSelector, setRule, type RuleRow } from "../../../../core/policy/rules.js";

export default defineEventHandler(async (event): Promise<Rule> => {
  await requireAdmin(event);
  const id = getRouterParam(event, "id") ?? "";
  const body = await readJsonBody(event);
  if (!getClientRow(id)) apiError(404, "not_found", "Client not found");
  const mailboxId = trimmedString(body.mailboxId, 100);
  const folder = typeof body.folder === "string" ? body.folder.trim() : "";
  const op = body.operation;
  const effect = body.effect;
  if (!getMailbox(mailboxId)) apiError(400, "validation", "Unknown mailbox");
  if (!isValidSelector(folder)) apiError(400, "validation", "Invalid folder selector: use an exact path, *, or Prefix/* (no other wildcards)");
  if (!isOperation(op)) apiError(400, "validation", "Unknown operation");
  if (effect !== "allow" && effect !== "deny") apiError(400, "validation", "Effect must be allow or deny");
  const db = getDb();
  setRule(db, id, mailboxId, folder, op, effect);
  const row = db
    .prepare("SELECT id, client_id, mailbox_id, folder, operation, effect, created_at FROM policy_rules WHERE client_id = ? AND mailbox_id = ? AND folder = ? AND operation = ?")
    .get(id, mailboxId, folder, op) as RuleRow;
  setResponseStatus(event, 201);
  return toRuleDto(row);
});
