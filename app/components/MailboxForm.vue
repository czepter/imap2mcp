<script setup lang="ts">
import { LoaderCircle } from "@lucide/vue";
import type { Mailbox, MailboxInput } from "~~/shared/types/api";

const props = defineProps<{
  mode: "create" | "edit";
  initial?: Pick<Mailbox, "label" | "host" | "port" | "username">;
  pending?: boolean;
  /** Error returned by the server for the last submit. */
  error?: string;
}>();
const emit = defineEmits<{ submit: [input: MailboxInput] }>();

const form = reactive({ label: "", host: "", port: 993 as number | string, username: "", password: "" });
const errors = reactive({ label: "", host: "", port: "", username: "", password: "" });

function reset() {
  form.label = props.initial?.label ?? "";
  form.host = props.initial?.host ?? "";
  form.port = props.initial?.port ?? 993;
  form.username = props.initial?.username ?? "";
  form.password = "";
  for (const k of Object.keys(errors) as (keyof typeof errors)[]) errors[k] = "";
}
watch(() => props.initial, reset, { immediate: true });

const uid = useId();
const ids = { label: `${uid}-label`, host: `${uid}-host`, port: `${uid}-port`, username: `${uid}-user`, password: `${uid}-pass` };
const root = useTemplateRef<HTMLFormElement>("root");

function validate(): MailboxInput | null {
  const label = form.label.trim();
  const host = form.host.trim();
  const port = typeof form.port === "number" ? form.port : Number.parseInt(String(form.port), 10);
  const username = form.username.trim();
  errors.label = label && label.length <= 100 ? "" : "Label is required (max 100 characters)";
  errors.host = host && host.length <= 253 && !/[\s/@:]/.test(host.replace(/^\[.*\]$/, "x")) ? "" : "A valid host name is required";
  errors.port = Number.isInteger(port) && port >= 1 && port <= 65535 ? "" : "Port must be 1-65535";
  errors.username = username && username.length <= 320 ? "" : "Username is required";
  errors.password = props.mode === "create" && !form.password ? "Password is required" : "";
  if (Object.values(errors).some(Boolean)) return null;
  const input: MailboxInput = { label, host, port, username };
  if (form.password) input.password = form.password;
  return input;
}

async function submit() {
  if (props.pending) return;
  const input = validate();
  if (!input) {
    await nextTick();
    root.value?.querySelector<HTMLElement>("[aria-invalid='true']")?.focus();
    return;
  }
  emit("submit", input);
}
</script>

<template>
  <form ref="root" autocomplete="off" novalidate class="grid gap-[14px] p-[18px]" @submit.prevent="submit">
    <div aria-live="polite">
      <ErrorAlert :error="error" />
    </div>

    <div class="grid gap-[5px] sm:max-w-[340px]">
      <Label :for="ids.label">Label</Label>
      <Input :id="ids.label" v-model="form.label" type="text" name="label" maxlength="100" required :aria-invalid="errors.label ? true : undefined" :aria-describedby="`${ids.label}-err`" />
      <p :id="`${ids.label}-err`" class="text-danger text-[13px]" :class="{ hidden: !errors.label }">{{ errors.label }}</p>
    </div>

    <div class="grid gap-[14px] sm:grid-cols-[minmax(0,1fr)_140px]">
      <div class="grid content-start gap-[5px]">
        <Label :for="ids.host">IMAP host</Label>
        <Input :id="ids.host" v-model="form.host" type="text" name="host" maxlength="253" required inputmode="url" autocapitalize="off" spellcheck="false" :aria-invalid="errors.host ? true : undefined" :aria-describedby="`${ids.host}-err`" />
        <p :id="`${ids.host}-err`" class="text-danger text-[13px]" :class="{ hidden: !errors.host }">{{ errors.host }}</p>
      </div>
      <div class="grid content-start gap-[5px]">
        <Label :for="ids.port">Port (TLS)</Label>
        <Input :id="ids.port" v-model="form.port" type="number" name="port" min="1" max="65535" required :aria-invalid="errors.port ? true : undefined" :aria-describedby="`${ids.port}-err`" />
        <p :id="`${ids.port}-err`" class="text-danger text-[13px]" :class="{ hidden: !errors.port }">{{ errors.port }}</p>
      </div>
    </div>

    <div class="grid gap-[5px]">
      <Label :for="ids.username">Username</Label>
      <Input :id="ids.username" v-model="form.username" type="text" name="username" maxlength="320" required autocapitalize="off" spellcheck="false" :aria-invalid="errors.username ? true : undefined" :aria-describedby="`${ids.username}-err`" />
      <p :id="`${ids.username}-err`" class="text-danger text-[13px]" :class="{ hidden: !errors.username }">{{ errors.username }}</p>
    </div>

    <div class="grid gap-[5px]">
      <Label :for="ids.password">Password</Label>
      <Input
        :id="ids.password"
        v-model="form.password"
        type="password"
        name="password"
        autocomplete="new-password"
        :required="mode === 'create'"
        :placeholder="mode === 'edit' ? 'Leave empty to keep the saved password' : undefined"
        :aria-invalid="errors.password ? true : undefined"
        :aria-describedby="`${ids.password}-err ${ids.password}-hint`"
      />
      <p :id="`${ids.password}-err`" class="text-danger text-[13px]" :class="{ hidden: !errors.password }">{{ errors.password }}</p>
      <p :id="`${ids.password}-hint`" class="text-muted-foreground text-[13px]">Stored encrypted. TLS with certificate validation is always on.</p>
    </div>

    <div>
      <Button type="submit" :disabled="pending">
        <LoaderCircle v-if="pending" class="animate-spin" aria-hidden="true" />
        {{ mode === "edit" ? "Save connection" : "Add mailbox" }}
      </Button>
    </div>
  </form>
</template>
