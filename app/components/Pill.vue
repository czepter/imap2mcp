<script setup lang="ts">
/** The design's .pill: ok / off (danger) / warn / read (neutral outline) / draft / organize. */
defineProps<{ tone?: "ok" | "off" | "warn" | "read" | "draft" | "organize" | "danger" | "success" | "warning" | "neutral" }>();
</script>

<template>
  <span
    class="inline-block rounded-full px-[9px] py-px text-xs leading-normal font-semibold whitespace-nowrap"
    :class="{
      'bg-ok-soft text-ok': tone === 'ok' || tone === 'success',
      'bg-danger-soft text-danger': tone === 'off' || tone === 'danger',
      'bg-warn-soft text-warn': tone === 'warn' || tone === 'warning' || tone === 'draft' || tone === 'organize',
      'bg-warn-soft text-warn shadow-[inset_0_0_0_1px_var(--warn)]': tone === 'organize',
      'bg-background text-foreground shadow-[inset_0_0_0_1px_var(--line-strong)]': !tone || tone === 'read' || tone === 'neutral',
    }"
  ><slot /></span>
</template>
