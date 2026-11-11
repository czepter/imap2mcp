<script setup lang="ts">
import { LoaderCircle } from "@lucide/vue";
import type { LoginRequest } from "~~/shared/types/api";

definePageMeta({ layout: "auth" });
useHead({ title: "Admin sign-in" });

const api = useApi();
const session = useSessionState();
const route = useRoute();

const password = ref("");
const error = ref("");
const pending = ref(false);
const pwInput = useTemplateRef<{ $el: HTMLInputElement }>("pwInput");

onMounted(() => pwInput.value?.$el?.focus());

async function submit() {
  if (pending.value) return;
  error.value = "";
  pending.value = true;
  try {
    await api.post<void>("/login", { password: password.value } satisfies LoginRequest);
    password.value = "";
    await session.refresh(); // new session, new CSRF token
    await navigateTo(safeReturnTo(route.query.returnTo) ?? "/dashboard", { replace: true });
  } catch (e) {
    const err = e instanceof ApiError ? e : null;
    error.value = err?.status === 401 ? "Wrong password. Try again." : (err?.message ?? "Sign-in failed. Try again.");
    password.value = "";
    pwInput.value?.$el?.focus();
  } finally {
    pending.value = false;
  }
}
</script>

<template>
  <form novalidate @submit.prevent="submit">
    <h1>Admin sign-in</h1>
    <p class="text-muted-foreground mt-1 text-[13px]">Manage mailboxes and what each AI client may do with them.</p>
    <div aria-live="assertive" class="mt-4 empty:hidden">
      <Notice v-if="error" kind="err">{{ error }}</Notice>
    </div>
    <div class="mt-[14px] grid gap-[5px]">
      <Label for="pw">Password</Label>
      <Input id="pw" ref="pwInput" v-model="password" type="password" name="password" required autocomplete="current-password" :aria-invalid="error ? true : undefined" />
    </div>
    <Button type="submit" class="mt-5 w-full" :disabled="pending || !password">
      <LoaderCircle v-if="pending" class="animate-spin" aria-hidden="true" />
      Sign in
    </Button>
  </form>
</template>
