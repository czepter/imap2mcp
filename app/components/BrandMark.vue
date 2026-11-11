<script setup lang="ts">
/** The design's shield-with-envelope mark. `onDark` (sidebar) uses the fixed light-blue shield; otherwise the brand colours. */
defineProps<{ onDark?: boolean }>();
</script>

<template>
  <svg viewBox="0 0 24 24" aria-hidden="true">
    <path d="M12 2l8 3v6c0 5-3.4 9.2-8 11-4.6-1.8-8-6-8-11V5z" :fill="onDark ? '#7ba0ff' : 'var(--brand)'" />
    <path d="M7.5 10.5l4.5 3 4.5-3M7.5 10.5h9v5h-9z" fill="none" :stroke="onDark ? '#10151f' : 'var(--brand-ink)'" stroke-width="1.4" stroke-linejoin="round" />
  </svg>
</template>
