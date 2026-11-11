<script setup lang="ts">
import type { Capability, GrantsUpdate } from "~~/shared/types/api";

type Grant = GrantsUpdate["grants"][number];

/**
 * Mailbox x capability checkbox matrix (design: 22px checkboxes, dashed hatched when unavailable).
 * Used by the client page (all capabilities) and the consent page (only the requested ones). The draft
 * column is unavailable for a mailbox without a Drafts folder unless it is already on (so an existing
 * grant can still be removed).
 */
const props = defineProps<{
  mailboxes: { id: string; label: string; draftsFolder: string | null }[];
  capabilities: Capability[];
  modelValue: Grant[];
  /** Who the grants are for; only used in the accessible names of the checkboxes. */
  subject: string;
  /** Prefix of the accessible names, e.g. "Allow" (consent) -> "Allow read on Work"; default "<subject>:". */
  labelPrefix?: string;
  disabled?: boolean;
}>();
const emit = defineEmits<{ "update:modelValue": [Grant[]] }>();

// Toggles are computed from this local copy, never from the props: two toggles in the same tick
// (before the parent re-rendered) must both survive.
const local = ref<Grant[]>(props.modelValue.slice());
watch(() => props.modelValue, (v) => { local.value = v.slice(); });

const isOn = (mailboxId: string, capability: Capability) =>
  local.value.some((g) => g.mailboxId === mailboxId && g.capability === capability);

const unavailable = (m: { id: string; draftsFolder: string | null }, capability: Capability) =>
  capability === "draft" && !m.draftsFolder && !isOn(m.id, capability);

function set(mailboxId: string, capability: Capability, on: boolean) {
  const rest = local.value.filter((g) => !(g.mailboxId === mailboxId && g.capability === capability));
  local.value = on ? [...rest, { mailboxId, capability }] : rest;
  emit("update:modelValue", local.value);
}

const label = (m: { label: string }, capability: Capability, off: boolean) =>
  off
    ? `${capability} on ${m.label} unavailable: no Drafts folder`
    : `${props.labelPrefix ?? `${props.subject}:`} ${capability} on ${m.label}`;
</script>

<template>
  <Table>
    <caption class="sr-only">Capabilities granted per mailbox</caption>
    <TableHeader>
      <TableRow>
        <TableHead scope="col">Mailbox</TableHead>
        <TableHead v-for="c in capabilities" :key="c" scope="col" class="c">{{ c }}</TableHead>
      </TableRow>
    </TableHeader>
    <TableBody>
      <TableRow v-for="m in mailboxes" :key="m.id">
        <TableHead scope="row">
          <span class="break-words">{{ m.label }}</span>
          <div v-if="!m.draftsFolder" class="text-muted-foreground text-[13px] font-normal">No Drafts folder yet</div>
        </TableHead>
        <TableCell v-for="c in capabilities" :key="c" class="c">
          <Checkbox
            :model-value="isOn(m.id, c)"
            :disabled="disabled || unavailable(m, c)"
            :aria-label="label(m, c, unavailable(m, c))"
            @update:model-value="(v: boolean | 'indeterminate') => set(m.id, c, v === true)"
          />
        </TableCell>
      </TableRow>
    </TableBody>
  </Table>
</template>
