import { Readable } from "node:stream";
import { getQuery, sendStream, setResponseHeader, type H3Event } from "h3";
import { auditExportLines, auditFilterFrom } from "./dto-audit";

/** Stream the audit export (headers as before). The response is pulled chunk by chunk, never buffered whole. */
export function sendAuditExport(event: H3Event, format: "jsonl" | "csv") {
  const f = auditFilterFrom(getQuery(event) as Record<string, unknown>);
  setResponseHeader(event, "Content-Type", format === "csv" ? "text/csv; charset=utf-8" : "application/x-ndjson; charset=utf-8");
  setResponseHeader(event, "Content-Disposition", `attachment; filename="audit.${format}"`);
  setResponseHeader(event, "Cache-Control", "no-store");
  function* chunks(): Generator<string> {
    for (const lines of auditExportLines(format, f)) yield lines.join("\n") + "\n";
  }
  return sendStream(event, Readable.from(chunks(), { objectMode: false }));
}
