<script setup lang="ts">
/** Shows the message of an ApiError (or any error / string) as the design's error alert. Renders nothing for a falsy error. */
defineProps<{ error: unknown; title?: string }>();

function messageOf(e: unknown): string {
  if (!e) return "";
  if (typeof e === "string") return e;
  if (e instanceof Error) return e.message;
  return "Something went wrong.";
}
</script>

<template>
  <Notice v-if="error" kind="err">
    <b v-if="title">{{ title }}. </b><slot>{{ messageOf(error) }}</slot>
    <template v-if="$slots.actions" #action><slot name="actions" /></template>
  </Notice>
</template>
