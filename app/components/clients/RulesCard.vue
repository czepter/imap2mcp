<script setup lang="ts">
import { toast } from "vue-sonner";
import { ApiError } from "~/composables/useApi";
import type { ClientDetail, Effect, Operation, Rule } from "~~/shared/types/api";

const props = defineProps<{ clientId: string; detail: ClientDetail }>();
const emit = defineEmits<{ changed: [] }>();

const api = useApi();
const uid = useId();
const labels = computed(() => new Map(props.detail.mailboxes.map((m) => [m.id, m.label])));
const mailboxLabel = (id: string) => labels.value.get(id) ?? id;

const presetText = (cap: "read" | "draft" | "organize") => props.detail.help.presetOperations[cap].join(", ");

// ---- add rule
const mailboxId = ref("");
const folder = ref("");
const operation = ref<string>("");
const effect = ref<string>("allow");
const adding = ref(false);
const addError = ref("");

watch(
  () => props.detail.mailboxes,
  (list) => { if (!list.some((m) => m.id === mailboxId.value)) mailboxId.value = list[0]?.id ?? ""; },
  { immediate: true },
);
watch(
  () => props.detail.help.operations,
  (list) => { if (!operation.value && list[0]) operation.value = list[0].operation; },
  { immediate: true },
);

async function addRule() {
  addError.value = "";
  const f = folder.value.trim();
  if (!f) { addError.value = "Enter a folder: an exact path, *, or Prefix/*."; return; }
  if (!mailboxId.value || !operation.value) return;
  adding.value = true;
  try {
    await api.post<Rule>(`/clients/${encodeURIComponent(props.clientId)}/rules`, {
      mailboxId: mailboxId.value, folder: f, operation: operation.value as Operation, effect: effect.value as Effect,
    });
    folder.value = "";
    toast.success("Rule saved.");
    emit("changed");
  } catch (e) {
    addError.value = e instanceof ApiError ? e.message : "Could not save the rule.";
  } finally {
    adding.value = false;
  }
}

// ---- remove rule
const removing = ref<string | null>(null);
const listError = ref("");
async function removeRule(r: Rule) {
  listError.value = "";
  removing.value = r.id;
  try {
    await api.del(`/clients/${encodeURIComponent(props.clientId)}/rules/${encodeURIComponent(r.id)}`);
    toast.success("Rule removed.");
    emit("changed");
  } catch (e) {
    listError.value = e instanceof ApiError ? e.message : "Could not remove the rule.";
  } finally {
    removing.value = null;
  }
}
</script>

<template>
  <SectionCard id="rules" title="Advanced rules">
    <p class="text-muted-foreground px-[18px] pt-[18px] text-[13px]">
      Presets above expand to allow rules on all folders (<code class="font-mono text-xs">*</code>):
      read = {{ presetText("read") }}; draft = {{ presetText("draft") }}; organize = {{ presetText("organize") }}.
      A matching <b class="text-foreground">deny</b> always wins; no matching allow means denied. Folder: exact IMAP path (case-sensitive),
      <code class="font-mono text-xs">*</code>, or <code class="font-mono text-xs">Prefix/*</code> for sub-folders. Renaming a folder
      on the server makes an exact rule stop matching (fails closed).
    </p>

    <div v-if="listError" class="px-[18px] pt-3"><ErrorAlert :error="listError" /></div>

    <div class="mt-3">
      <Table v-if="detail.rules.length">
        <caption class="sr-only">Rules for this client</caption>
        <TableHeader>
          <TableRow>
            <TableHead scope="col">Mailbox</TableHead>
            <TableHead scope="col">Folder</TableHead>
            <TableHead scope="col">Operation</TableHead>
            <TableHead scope="col">Effect</TableHead>
            <TableHead scope="col"><span class="sr-only">Actions</span></TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow v-for="r in detail.rules" :key="r.id">
            <TableCell class="break-words">{{ mailboxLabel(r.mailboxId) }}</TableCell>
            <TableCell>
              <span class="font-mono text-xs break-all">{{ r.folder }}</span>
              <Pill v-if="!r.selectorValid" tone="warn" class="ml-1.5">invalid, never matches</Pill>
            </TableCell>
            <TableCell>{{ r.operation }}</TableCell>
            <TableCell><b>{{ r.effect }}</b></TableCell>
            <TableCell class="r">
              <Button
                variant="outline"
                size="sm"
                :disabled="removing === r.id"
                :aria-label="`Remove rule: ${r.effect} ${r.operation} on ${r.folder} in ${mailboxLabel(r.mailboxId)}`"
                @click="removeRule(r)"
              >
                {{ removing === r.id ? "Removing…" : "Remove" }}
              </Button>
            </TableCell>
          </TableRow>
        </TableBody>
      </Table>
      <EmptyState v-else title="No rules." />
    </div>

    <form v-if="detail.mailboxes.length" class="grid gap-3.5 border-t p-[18px]" @submit.prevent="addRule">
      <h3 class="text-sm font-semibold">Add rule</h3>
      <ErrorAlert :error="addError" />
      <div class="grid gap-x-3.5 gap-y-3.5 sm:grid-cols-2">
        <div class="grid content-start gap-[5px]">
          <Label :for="`${uid}-mailbox`">Mailbox</Label>
          <Select v-model="mailboxId">
            <SelectTrigger :id="`${uid}-mailbox`"><SelectValue placeholder="Choose a mailbox" /></SelectTrigger>
            <SelectContent>
              <SelectItem v-for="m in detail.mailboxes" :key="m.id" :value="m.id">{{ m.label }}</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div class="grid content-start gap-[5px]">
          <Label :for="`${uid}-folder`">Folder (exact path, <code class="font-mono text-xs">*</code>, or <code class="font-mono text-xs">Prefix/*</code>)</Label>
          <Input :id="`${uid}-folder`" v-model="folder" type="text" maxlength="255" required autocomplete="off" spellcheck="false" />
        </div>
        <div class="grid content-start gap-[5px]">
          <Label :for="`${uid}-operation`">Operation</Label>
          <Select v-model="operation">
            <SelectTrigger :id="`${uid}-operation`"><SelectValue placeholder="Choose an operation" /></SelectTrigger>
            <SelectContent>
              <SelectItem v-for="o in detail.help.operations" :key="o.operation" :value="o.operation">
                {{ o.operation }} (needs {{ o.capability }})
              </SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div class="grid content-start gap-[5px]">
          <Label :for="`${uid}-effect`">Effect</Label>
          <Select v-model="effect">
            <SelectTrigger :id="`${uid}-effect`"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="allow">allow</SelectItem>
              <SelectItem value="deny">deny</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>
      <div><Button type="submit" size="sm" :disabled="adding">{{ adding ? "Adding…" : "Add rule" }}</Button></div>
    </form>
  </SectionCard>
</template>
