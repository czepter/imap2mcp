<script setup lang="ts">
import { LoaderCircle } from "@lucide/vue";
import type { SetupRequest } from "~~/shared/types/api";

definePageMeta({ layout: "auth" });
useHead({ title: "Initial setup" });

const MIN_PASSWORD = 12;
const api = useApi();
const session = useSessionState();

const form = reactive({ token: "", password: "", password2: "" });
const fieldErrors = reactive({ token: "", password: "", password2: "" });
const error = ref("");
const pending = ref(false);
const root = useTemplateRef<HTMLFormElement>("root");

function validate(): boolean {
  fieldErrors.token = form.token ? "" : "Enter the bootstrap token from the server log";
  fieldErrors.password = form.password.length >= MIN_PASSWORD ? "" : `Password must be at least ${MIN_PASSWORD} characters`;
  fieldErrors.password2 = form.password === form.password2 ? "" : "Passwords do not match";
  return !fieldErrors.token && !fieldErrors.password && !fieldErrors.password2;
}

async function submit() {
  if (pending.value) return;
  error.value = "";
  if (!validate()) {
    await nextTick();
    root.value?.querySelector<HTMLElement>("[aria-invalid='true']")?.focus();
    return;
  }
  pending.value = true;
  try {
    await api.post<void>("/setup", { token: form.token, password: form.password, password2: form.password2 } satisfies SetupRequest);
    form.token = form.password = form.password2 = "";
    await session.refresh();
    await navigateTo("/dashboard", { replace: true });
  } catch (e) {
    error.value = e instanceof ApiError ? (e.status === 404 ? "Setup is already complete. Sign in instead." : e.message) : "Setup failed. Try again.";
  } finally {
    pending.value = false;
  }
}
</script>

<template>
  <form ref="root" novalidate @submit.prevent="submit">
    <h1>Initial setup</h1>
    <p class="text-muted-foreground mt-1 text-[13px]">Create the admin account. You need the one-time bootstrap token that the server printed on its first start.</p>
    <div aria-live="assertive" class="mt-4 empty:hidden">
      <Notice v-if="error" kind="err">{{ error }}</Notice>
    </div>

    <div class="mt-[14px] grid gap-[5px]">
      <Label for="t">Bootstrap token (printed in the server log)</Label>
      <Input id="t" v-model="form.token" type="password" name="token" required autocomplete="off" :aria-invalid="fieldErrors.token ? true : undefined" aria-describedby="t-err" />
      <p id="t-err" class="text-danger text-[13px]" :class="{ hidden: !fieldErrors.token }">{{ fieldErrors.token }}</p>
    </div>
    <div class="mt-[14px] grid gap-[5px]">
      <Label for="p1">Admin password (min {{ MIN_PASSWORD }} chars)</Label>
      <Input id="p1" v-model="form.password" type="password" name="password" required :minlength="MIN_PASSWORD" autocomplete="new-password" :aria-invalid="fieldErrors.password ? true : undefined" aria-describedby="p1-err" />
      <p id="p1-err" class="text-danger text-[13px]" :class="{ hidden: !fieldErrors.password }">{{ fieldErrors.password }}</p>
    </div>
    <div class="mt-[14px] grid gap-[5px]">
      <Label for="p2">Repeat password</Label>
      <Input id="p2" v-model="form.password2" type="password" name="password2" required :minlength="MIN_PASSWORD" autocomplete="new-password" :aria-invalid="fieldErrors.password2 ? true : undefined" aria-describedby="p2-err" />
      <p id="p2-err" class="text-danger text-[13px]" :class="{ hidden: !fieldErrors.password2 }">{{ fieldErrors.password2 }}</p>
    </div>

    <Button type="submit" class="mt-5 w-full" :disabled="pending">
      <LoaderCircle v-if="pending" class="animate-spin" aria-hidden="true" />
      Create admin
    </Button>
  </form>
</template>
