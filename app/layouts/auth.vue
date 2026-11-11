<script setup lang="ts">
/**
 * Centered panel (design: .center > .panel) with the brand row, for setup, sign-in and the OAuth consent page.
 * Pages put their own h1 and content in the slot. Wide (560px, consent):
 * `definePageMeta({ layout: { name: "auth", props: { wide: true } } })`.
 */
defineProps<{ wide?: boolean }>();
</script>

<template>
  <main id="main" class="center">
    <div class="panel" :class="{ wide }">
      <div class="brand"><BrandMark />IMAP Bridge</div>
      <slot />
    </div>
  </main>
</template>
