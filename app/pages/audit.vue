<script setup lang="ts">
import { ApiError } from "~/composables/useApi";
import type { AuditEvent, AuditOutcome, AuditPage } from "~~/shared/types/api";

useHead({ title: "Audit log" });

const route = useRoute();
const router = useRouter();
const api = useApi();

const ALL = "__all__";
const OUTCOMES: AuditOutcome[] = ["ok", "denied", "failed", "unknown_outcome"];
const DATE = /^\d{4}-\d{2}-\d{2}$/;

const one = (v: unknown): string => (typeof v === "string" ? v : Array.isArray(v) && typeof v[0] === "string" ? v[0] : "");

/** The filters that are applied right now: always derived from the URL, so a link or reload reproduces them. */
const applied = computed(() => {
  const o = one(route.query.outcome);
  return {
    client: one(route.query.client).trim().slice(0, 128),
    mailbox: one(route.query.mailbox).trim().slice(0, 128),
    tool: one(route.query.tool).trim().slice(0, 128),
    outcome: (OUTCOMES as string[]).includes(o) ? o : "",
    from: DATE.test(one(route.query.from)) ? one(route.query.from) : "",
    to: DATE.test(one(route.query.to)) ? one(route.query.to) : "",
  };
});
const hasFilters = computed(() => Object.values(applied.value).some(Boolean));
const pageNo = computed(() => Math.max(1, parseInt(one(route.query.page).slice(0, 8), 10) || 1));

const form = reactive({ ...applied.value });
watch(applied, (v) => Object.assign(form, v));

const qs = (filters: Record<string, string>, page?: number): string => {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(filters)) if (v) p.set(k, v);
  if (page && page > 1) p.set("page", String(page));
  const s = p.toString();
  return s ? `?${s}` : "";
};
const exportQuery = computed(() => qs(applied.value));
const pageTo = (n: number) => `/audit${qs(applied.value, n)}`;

function submit() {
  const q: Record<string, string> = {};
  for (const [k, v] of Object.entries(form)) {
    const t = (v as string).trim();
    if (t) q[k] = t;
  }
  router.push({ path: "/audit", query: q });
}
function reset() {
  Object.assign(form, { client: "", mailbox: "", tool: "", outcome: "", from: "", to: "" });
  router.push({ path: "/audit", query: {} });
}

// ---- data
const data = ref<AuditPage | null>(null);
const loading = ref(true);
const error = ref("");
let seq = 0;

async function load() {
  const mine = ++seq;
  loading.value = true;
  error.value = "";
  try {
    const query: Record<string, string | number> = {};
    for (const [k, v] of Object.entries(applied.value)) if (v) query[k] = v;
    if (pageNo.value > 1) query.page = pageNo.value;
    const res = await api.get<AuditPage>("/audit", { query });
    if (mine === seq) data.value = res;
  } catch (e) {
    if (mine === seq) error.value = e instanceof ApiError ? e.message : "Could not load the audit log.";
  } finally {
    if (mine === seq) loading.value = false;
  }
}
watch(() => `${exportQuery.value}|${pageNo.value}`, load, { immediate: true });

// A filter value from the URL stays selectable even before (or without) the server listing it.
const withCurrent = (list: string[] | undefined, current: string) =>
  current && !(list ?? []).includes(current) ? [...(list ?? []), current] : (list ?? []);
const clientOptions = computed(() => withCurrent(data.value?.options.clients, form.client));
const mailboxOptions = computed(() => withCurrent(data.value?.options.mailboxes, form.mailbox));
const toolOptions = computed(() => withCurrent(data.value?.options.tools, form.tool));
const outcomeOptions = computed(() => withCurrent([...new Set([...OUTCOMES, ...(data.value?.options.outcomes ?? [])])], form.outcome));

const sel = (v: unknown) => (v === ALL ? "" : String(v ?? ""));

// ---- rendering helpers
const ts = (iso: string) => iso.replace("T", " ").replace("Z", "");
const outcomeLabel = (o: string) => o.replace("_", " ");
const outcomeTone = (o: AuditOutcome) => (o === "ok" ? "ok" : o === "denied" ? "warn" : "off");
function uidCell(e: AuditEvent): string {
  if (e.uid !== null) return String(e.uid);
  if (e.uids) return `${e.uids.length} UIDs${e.uidsTruncated ? " (truncated)" : ""}`;
  return "";
}
const summary = computed(() => {
  const d = data.value;
  if (!d) return "";
  return `${d.total} event${d.total === 1 ? "" : "s"} · page ${d.page} of ${d.pages}`;
});
</script>

<template>
  <div>
    <PageHeader
      title="Audit log"
      description="Every tool attempt: who, which mailbox and message references, outcome. Never message content, headers or credentials."
    />

    <div class="grid gap-5">
      <SectionCard id="filter" title="Filter">
        <form class="grid gap-[18px] p-[18px]" @submit.prevent="submit">
          <div class="grid gap-x-3.5 gap-y-3.5 sm:grid-cols-2 lg:grid-cols-3">
            <div class="grid content-start gap-[5px]">
              <Label for="audit-client">Client</Label>
              <Select :model-value="form.client || ALL" @update:model-value="form.client = sel($event)">
                <SelectTrigger id="audit-client"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem :value="ALL">All clients</SelectItem>
                  <SelectItem v-for="c in clientOptions" :key="c" :value="c">{{ c }}</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div class="grid content-start gap-[5px]">
              <Label for="audit-mailbox">Mailbox</Label>
              <Select :model-value="form.mailbox || ALL" @update:model-value="form.mailbox = sel($event)">
                <SelectTrigger id="audit-mailbox"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem :value="ALL">All mailboxes</SelectItem>
                  <SelectItem v-for="m in mailboxOptions" :key="m" :value="m">{{ m }}</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div class="grid content-start gap-[5px]">
              <Label for="audit-tool">Tool</Label>
              <Select :model-value="form.tool || ALL" @update:model-value="form.tool = sel($event)">
                <SelectTrigger id="audit-tool"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem :value="ALL">All tools</SelectItem>
                  <SelectItem v-for="t in toolOptions" :key="t" :value="t">{{ t }}</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div class="grid content-start gap-[5px]">
              <Label for="audit-outcome">Outcome</Label>
              <Select :model-value="form.outcome || ALL" @update:model-value="form.outcome = sel($event)">
                <SelectTrigger id="audit-outcome"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem :value="ALL">All outcomes</SelectItem>
                  <SelectItem v-for="o in outcomeOptions" :key="o" :value="o">{{ outcomeLabel(o) }}</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div class="grid content-start gap-[5px]">
              <Label for="audit-from">From (UTC)</Label>
              <Input id="audit-from" v-model="form.from" type="date" />
            </div>
            <div class="grid content-start gap-[5px]">
              <Label for="audit-to">To (UTC, inclusive)</Label>
              <Input id="audit-to" v-model="form.to" type="date" />
            </div>
          </div>
          <div class="flex flex-wrap items-center gap-2.5">
            <Button type="submit">Filter</Button>
            <Button type="button" variant="outline" @click="reset">Reset</Button>
            <span class="flex-1" />
            <Button as-child variant="outline">
              <a :href="`/api/audit/export.jsonl${exportQuery}`" download>Download JSONL</a>
            </Button>
            <Button as-child variant="outline">
              <a :href="`/api/audit/export.csv${exportQuery}`" download>Download CSV</a>
            </Button>
          </div>
        </form>
      </SectionCard>

      <SectionCard id="events" title="Events">
        <template #aside><span aria-live="polite">{{ summary }}</span></template>

        <div v-if="error" class="p-[18px]">
          <ErrorAlert :error="error" title="Could not load the audit log">
            <template #actions>
              <Button variant="outline" size="sm" @click="load">Try again</Button>
            </template>
          </ErrorAlert>
        </div>

        <!-- first load -->
        <TableSkeleton v-if="!data && loading" :rows="6" :cols="6" />

        <template v-else-if="data">
          <div v-if="data.events.length" :aria-busy="loading" :class="loading && 'opacity-60 transition-opacity'">
            <Table>
              <caption class="sr-only">Audit events</caption>
              <TableHeader>
                <TableRow>
                  <TableHead scope="col">Time (UTC)</TableHead>
                  <TableHead scope="col">Client</TableHead>
                  <TableHead scope="col">Mailbox</TableHead>
                  <TableHead scope="col">Folder</TableHead>
                  <TableHead scope="col">UIDVALIDITY</TableHead>
                  <TableHead scope="col">UID(s)</TableHead>
                  <TableHead scope="col">Tool</TableHead>
                  <TableHead scope="col">Outcome</TableHead>
                  <TableHead scope="col">Flags</TableHead>
                  <TableHead scope="col" class="r">ms</TableHead>
                  <TableHead scope="col">Request</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                <TableRow v-for="e in data.events" :key="e.id">
                  <TableCell class="font-mono text-xs">
                    <time :datetime="e.ts" class="whitespace-nowrap">{{ ts(e.ts) }}</time>
                  </TableCell>
                  <TableCell class="font-mono text-xs"><span class="whitespace-nowrap">{{ e.clientId }}</span><AuditNone v-if="!e.clientId" /></TableCell>
                  <TableCell class="font-mono text-xs"><span class="whitespace-nowrap">{{ e.mailboxId }}</span><AuditNone v-if="!e.mailboxId" /></TableCell>
                  <TableCell>{{ e.folder }}<AuditNone v-if="!e.folder" /></TableCell>
                  <TableCell>{{ e.uidValidity }}<AuditNone v-if="e.uidValidity === null" /></TableCell>
                  <TableCell><span class="whitespace-nowrap">{{ uidCell(e) }}</span><AuditNone v-if="!uidCell(e)" /></TableCell>
                  <TableCell><span class="whitespace-nowrap">{{ e.tool }}</span></TableCell>
                  <TableCell>
                    <Pill :tone="outcomeTone(e.outcome)">{{ outcomeLabel(e.outcome) }}</Pill>
                    <span v-if="e.errorCode" class="text-muted-foreground ml-1.5 text-[13px]">{{ e.errorCode }}</span>
                  </TableCell>
                  <TableCell>
                    <span class="inline-flex gap-1">
                      <Pill v-if="e.cached" tone="read">cached</Pill>
                      <Pill v-if="e.reconciled" tone="read">reconciled</Pill>
                    </span>
                  </TableCell>
                  <TableCell class="r">{{ e.durationMs }}</TableCell>
                  <TableCell class="font-mono text-xs"><span class="whitespace-nowrap">{{ e.requestId }}</span></TableCell>
                </TableRow>
              </TableBody>
            </Table>
          </div>
          <EmptyState v-else title="No audit events match." :description="hasFilters ? 'Widen the filters or reset them to see every event.' : undefined" />

          <div class="flex flex-wrap items-center justify-between gap-3 border-t px-[18px] py-3">
            <span class="text-muted-foreground text-[13px]">{{ summary }}</span>
            <div class="flex gap-2">
              <Button v-if="data.page > 1" as-child variant="outline" size="sm">
                <NuxtLink :to="pageTo(data.page - 1)">Previous</NuxtLink>
              </Button>
              <Button v-if="data.page < data.pages" as-child variant="outline" size="sm">
                <NuxtLink :to="pageTo(data.page + 1)">Next</NuxtLink>
              </Button>
            </div>
          </div>
        </template>
      </SectionCard>
    </div>
  </div>
</template>
