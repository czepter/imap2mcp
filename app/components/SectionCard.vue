<script setup lang="ts">
/**
 * The design's .card: 12px radius, header row (h2 left, muted hint/actions in slot `aside` right), body.
 * `padded` adds the 18px .pad. `danger` is the danger-zone variant (danger border, tinted header).
 */
const props = withDefaults(defineProps<{ id: string; title: string; description?: string; padded?: boolean; danger?: boolean }>(), { padded: false, danger: false });
const headingId = computed(() => `${props.id}-h`);
</script>

<template>
  <section
    :id="id"
    :aria-labelledby="headingId"
    class="bg-card scroll-mt-4 overflow-hidden rounded-xl border"
    :class="danger ? 'border-danger' : ''"
  >
    <header class="flex items-center justify-between gap-3 border-b px-[18px] py-3.5" :class="danger ? 'bg-danger-soft text-danger' : ''">
      <div class="min-w-0">
        <h2 :id="headingId">{{ title }}</h2>
        <p v-if="description" class="text-muted-foreground text-[13px]">{{ description }}</p>
      </div>
      <div v-if="$slots.aside" class="text-muted-foreground flex flex-wrap items-center justify-end gap-2 text-[13px]"><slot name="aside" /></div>
    </header>
    <div :class="padded ? 'p-[18px]' : ''"><slot /></div>
  </section>
</template>
