<script setup lang="ts">
const route = useRoute();
const crumbs = useCrumbState();
const { signOut, signingOut } = useSignOut();

/** One route per section. */
const items = [
  { label: "Overview", to: "/dashboard", match: (p: string) => p === "/dashboard" || p === "/" },
  { label: "Mailboxes", to: "/mailboxes", match: (p: string) => p.startsWith("/mailboxes") },
  { label: "Clients", to: "/clients", match: (p: string) => p.startsWith("/clients") },
  { label: "Tokens", to: "/tokens", match: (p: string) => p.startsWith("/tokens") },
  { label: "Audit log", to: "/audit", match: (p: string) => p.startsWith("/audit") },
];
</script>

<template>
  <div class="app">
    <a href="#main" class="bg-primary text-primary-foreground sr-only z-50 rounded-md px-3 py-2 text-sm font-medium focus:not-sr-only focus:fixed focus:top-2 focus:left-2">Skip to content</a>
    <aside class="side">
      <NuxtLink v-slot="{ href, navigate }" to="/dashboard" custom>
        <a :href="href ?? undefined" class="brand" @click="navigate"><BrandMark on-dark />IMAP Bridge</a>
      </NuxtLink>
      <nav aria-label="Main">
        <NuxtLink v-for="item in items" :key="item.to" v-slot="{ href, navigate }" :to="item.to" custom>
          <a :href="href ?? undefined" :aria-current="item.match(route.path) ? 'page' : undefined" @click="navigate">{{ item.label }}</a>
        </NuxtLink>
      </nav>
      <div class="foot">
        Signed in as admin<br>
        <button type="button" class="linkbtn" :disabled="signingOut" @click="signOut">Log out</button>
      </div>
    </aside>
    <main id="main" tabindex="-1" class="outline-none">
      <nav v-if="crumbs.length" aria-label="Breadcrumb" class="crumb">
        <template v-for="(c, i) in crumbs" :key="i">
          <template v-if="i > 0"> / </template>
          <NuxtLink v-if="c.to && i < crumbs.length - 1" :to="c.to">{{ c.label }}</NuxtLink>
          <span v-else :aria-current="i === crumbs.length - 1 ? 'page' : undefined">{{ c.label }}</span>
        </template>
      </nav>
      <slot />
    </main>
  </div>
</template>
