<script setup lang="ts">
import { toast } from "vue-sonner";
import type { TokenSummary } from "~~/shared/types/api";

useHead({ title: "Tokens" });

const api = useApi();
const { data, error, pending, refresh, tokens } = useOverview();

// Inline confirmation band under the row (design), one open at a time.
const confirmingId = ref<string | null>(null);
const revoking = ref(false);
const revokeError = ref("");
function toggleRevoke(t: TokenSummary) {
  revokeError.value = "";
  confirmingId.value = confirmingId.value === t.id ? null : t.id;
}
function revokeText(t: TokenSummary): string {
  const name = t.clientName || t.clientId;
  if (!t.reach.length) return ` ${name} has no access left through this token; revoking removes it. It can ask you to authorize again.`;
  const parts = t.reach.map((r) => `${joinList(sortCapabilities(r.capabilities))} on ${r.mailboxLabel}`);
  return ` ${name} loses ${joinList(parts)} right now. It can ask you to authorize again.`;
}
async function revokeToken(t: TokenSummary) {
  revoking.value = true;
  revokeError.value = "";
  try {
    await api.post(`/tokens/${encodeURIComponent(t.id)}/revoke`);
    confirmingId.value = null;
    toast.success("Token revoked.");
    await refresh();
  } catch (e) {
    revokeError.value = e instanceof ApiError ? e.message : "Could not revoke the token.";
  } finally {
    revoking.value = false;
  }
}
</script>

<template>
  <div>
    <PageHeader title="Tokens" description="The access tokens clients hold right now." />

    <ErrorAlert v-if="error && !data" :error="error" title="Could not load the tokens">
      <template #actions>
        <Button variant="outline" size="sm" @click="refresh({ quiet: false })">Try again</Button>
      </template>
    </ErrorAlert>

    <section v-else-if="pending && !data" class="bg-card overflow-hidden rounded-xl border" aria-busy="true">
      <TableSkeleton :rows="3" :cols="4" />
    </section>

    <SectionCard v-else-if="data" id="tokens" title="Active tokens">
      <template #aside><span>Revoking cuts access at the next call.</span></template>
      <EmptyState v-if="!tokens.length" title="No active tokens." />
      <Table v-else>
        <caption class="sr-only">Active access tokens</caption>
        <TableHeader>
          <TableRow>
            <TableHead scope="col">Client</TableHead>
            <TableHead scope="col">Can reach</TableHead>
            <TableHead scope="col">Issued</TableHead>
            <TableHead scope="col">Access token expires</TableHead>
            <TableHead scope="col"><span class="sr-only">Actions</span></TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          <template v-for="t in tokens" :key="t.id">
            <TableRow>
              <TableCell class="max-w-56 font-semibold break-words">{{ t.clientName || t.clientId }}</TableCell>
              <TableCell>
                <template v-if="t.reach.length">
                  <div v-for="r in t.reach" :key="r.mailboxId">{{ r.mailboxLabel }} <CapabilityBadges :capabilities="r.capabilities" /></div>
                </template>
                <span v-else class="text-muted-foreground">nothing (all grants removed)</span>
              </TableCell>
              <TableCell class="text-muted-foreground text-[13px]">{{ formatIssued(t.createdAt) }}</TableCell>
              <TableCell class="text-muted-foreground text-[13px]">{{ formatExpires(t.expiresAt) }}</TableCell>
              <TableCell class="r">
                <Button variant="outline" size="sm" class="btn-d" :aria-expanded="confirmingId === t.id" :aria-controls="`revoke-${t.id}`" @click="toggleRevoke(t)">
                  Revoke<span class="sr-only"> token of {{ t.clientName || t.clientId }}</span>
                </Button>
              </TableCell>
            </TableRow>
            <TableRow v-if="confirmingId === t.id" :id="`revoke-${t.id}`">
              <TableCell colspan="5" data-static class="!border-t-0 !p-0">
                <ConfirmBand
                  :title="`Revoke ${t.clientName || t.clientId}'s token?`"
                  confirm-label="Revoke token"
                  label="Confirm revoke"
                  :pending="revoking"
                  :error="revokeError"
                  @cancel="confirmingId = null"
                  @confirm="revokeToken(t)"
                >{{ revokeText(t) }}</ConfirmBand>
              </TableCell>
            </TableRow>
          </template>
        </TableBody>
      </Table>
    </SectionCard>
  </div>
</template>
