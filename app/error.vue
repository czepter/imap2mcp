<script setup lang="ts">
import type { NuxtError } from "#app";

const props = defineProps<{ error: NuxtError }>();
const notFound = computed(() => props.error.statusCode === 404);
const title = computed(() => (notFound.value ? "Page not found" : "Something went wrong"));
const message = computed(() => (notFound.value ? "That page does not exist." : props.error.message || "Unexpected error."));
useHead({ title });

function retry() { reloadNuxtApp({ path: "/", force: true }); }
</script>

<template>
  <div class="grid min-h-svh place-items-center px-4 py-10">
    <main class="w-full max-w-md">
      <Card>
        <CardHeader>
          <CardTitle class="text-xl">{{ title }}</CardTitle>
          <CardDescription>{{ message }}</CardDescription>
        </CardHeader>
        <CardFooter class="gap-2">
          <Button @click="retry">{{ notFound ? "Go to overview" : "Try again" }}</Button>
        </CardFooter>
      </Card>
    </main>
  </div>
</template>
