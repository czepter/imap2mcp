<script setup lang="ts">
import { LoaderCircle } from "@lucide/vue";

const props = withDefaults(defineProps<{
  title: string;
  description?: string;
  confirmLabel: string;
  cancelLabel?: string;
  /** Styles the confirm button as destructive. */
  destructive?: boolean;
  /** When set, the user must type exactly this text before the confirm button enables. */
  confirmText?: string;
  /** Parent-controlled: true while the confirmed action runs (buttons disabled, dialog cannot be dismissed). */
  pending?: boolean;
  /** Error from the confirmed action, shown inside the dialog so the user can retry. */
  error?: unknown;
}>(), { cancelLabel: "Cancel" });

const open = defineModel<boolean>("open", { default: false });
const emit = defineEmits<{ confirm: [] }>();

const typed = ref("");
const inputId = useId();
watch(open, (v) => { if (v) typed.value = ""; });

const canConfirm = computed(() => !props.pending && (!props.confirmText || typed.value === props.confirmText));
const errorText = computed(() => {
  const e = props.error;
  if (!e) return "";
  return typeof e === "string" ? e : e instanceof Error ? e.message : "Something went wrong.";
});

function onOpenChange(v: boolean) {
  if (!v && props.pending) return; // never dismiss mid-request
  open.value = v;
}
function confirm() {
  if (canConfirm.value) emit("confirm");
}
</script>

<template>
  <AlertDialog :open="open" @update:open="onOpenChange">
    <AlertDialogContent>
      <AlertDialogHeader>
        <AlertDialogTitle>{{ title }}</AlertDialogTitle>
        <AlertDialogDescription v-if="description || $slots.description" as="div">
          <slot name="description">{{ description }}</slot>
        </AlertDialogDescription>
      </AlertDialogHeader>

      <slot />

      <form v-if="confirmText" class="grid gap-2" @submit.prevent="confirm">
        <Label :for="inputId">Type <strong class="font-semibold break-all">{{ confirmText }}</strong> to confirm</Label>
        <Input :id="inputId" v-model="typed" type="text" autocomplete="off" autocapitalize="off" spellcheck="false" :disabled="pending" />
      </form>

      <div aria-live="polite">
        <Notice v-if="errorText" kind="err">{{ errorText }}</Notice>
      </div>

      <AlertDialogFooter>
        <AlertDialogCancel :disabled="pending">{{ cancelLabel }}</AlertDialogCancel>
        <Button :variant="destructive ? 'destructive' : 'default'" :disabled="!canConfirm" :aria-busy="pending" @click="confirm">
          <LoaderCircle v-if="pending" class="animate-spin" aria-hidden="true" />
          {{ confirmLabel }}
        </Button>
      </AlertDialogFooter>
    </AlertDialogContent>
  </AlertDialog>
</template>
