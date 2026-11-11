import { defineEventHandler, getQuery } from "h3";
import type { AuditPage } from "../../../shared/types/api";
import { requireAdmin } from "../../utils/requireAdmin";
import { AUDIT_OUTCOMES, AUDIT_PAGE_SIZE, auditFilterFrom, queryString, toAuditEventDto } from "../../utils/dto-audit";
import { countAudit, distinctValues, queryAudit } from "../../core/audit/store.js";

export default defineEventHandler(async (event): Promise<AuditPage> => {
  await requireAdmin(event);
  const query = getQuery(event) as Record<string, unknown>;
  const f = auditFilterFrom(query);
  const total = countAudit(f);
  const pages = Math.max(1, Math.ceil(total / AUDIT_PAGE_SIZE));
  const page = Math.min(Math.max(parseInt(queryString(query.page, 8), 10) || 1, 1), pages);
  const events = queryAudit(f, { limit: AUDIT_PAGE_SIZE, offset: (page - 1) * AUDIT_PAGE_SIZE }).map(toAuditEventDto);
  return {
    events, total, page, pages, pageSize: AUDIT_PAGE_SIZE,
    options: {
      clients: distinctValues("client_id"),
      mailboxes: distinctValues("mailbox_id"),
      tools: distinctValues("tool"),
      outcomes: [...AUDIT_OUTCOMES],
    },
  };
});
