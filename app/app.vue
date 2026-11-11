<script setup lang="ts">
useHead({ titleTemplate: (title) => (title ? `${title} - IMAP Bridge` : "IMAP Bridge") });
</script>

<template>
  <NuxtLayout>
    <NuxtPage />
  </NuxtLayout>
  <Toaster position="bottom-right" theme="system" close-button />
</template>
