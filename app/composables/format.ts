import type { Capability } from "~~/shared/types/api";

/** Display order of capabilities everywhere. */
export const CAPABILITY_ORDER: Capability[] = ["read", "draft", "organize"];

export function sortCapabilities(caps: readonly Capability[]): Capability[] {
  return CAPABILITY_ORDER.filter((c) => caps.includes(c));
}

/** "2026-11-10T14:05:33Z" -> "2026-11-10 14:05 UTC" (same format as the old UI). */
export function formatWhen(iso: string | null | undefined): string {
  if (!iso) return "";
  return `${iso.replace("T", " ").slice(0, 16)} UTC`;
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const pad = (n: number) => String(n).padStart(2, "0");
/** Timestamps from the API are UTC; tolerate "YYYY-MM-DD HH:MM:SS" without the zone. */
function toDate(iso: string): Date {
  return new Date(/[zZ]|[+-]\d\d:?\d\d$/.test(iso) ? iso : `${iso.replace(" ", "T")}Z`);
}

/** "Nov 6, 09:12" in the viewer's local time (design format for the token table). */
export function formatIssued(iso: string): string {
  const d = toDate(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return `${MONTHS[d.getMonth()]} ${d.getDate()}, ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/** "today, 10:12 (in 41 min)" / "Nov 11, 10:12" / "expired" (design format for token expiry). */
export function formatExpires(iso: string, now: Date = new Date()): string {
  const d = toDate(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const diffMin = Math.round((d.getTime() - now.getTime()) / 60000);
  if (diffMin <= 0) return `${formatIssued(iso)} (expired)`;
  const sameDay = d.toDateString() === now.toDateString();
  const rel = diffMin < 60 ? `in ${diffMin} min` : diffMin < 1440 ? `in ${Math.round(diffMin / 60)} h` : `in ${Math.round(diffMin / 1440)} d`;
  return sameDay ? `today, ${pad(d.getHours())}:${pad(d.getMinutes())} (${rel})` : `${formatIssued(iso)} (${rel})`;
}

/** ["a", "b", "c"] -> "a, b and c" */
export function joinList(items: readonly string[]): string {
  if (items.length <= 1) return items.join("");
  return `${items.slice(0, -1).join(", ")} and ${items[items.length - 1]}`;
}
