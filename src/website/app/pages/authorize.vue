<template>
  <div class="min-h-screen flex items-center justify-center p-8">
    <div class="card w-full max-w-lg bg-base-300 shadow-xl">
      <div class="card-body">
        <h1 class="card-title text-3xl">AbandonAuth</h1>

        <p v-if="state === 'loading'" class="mt-4">Loading the request…</p>

        <p v-else-if="state === 'unavailable'" class="mt-4" data-test="unavailable">{{ unavailableMessage }}</p>

        <template v-else-if="pending">
          <p class="mt-4 text-lg"><span class="font-bold" data-test="application-name">{{ pending.application_name }}</span> wants you to sign in.</p>

          <ul class="mt-4 list-disc pl-6 space-y-2" data-test="permissions">
            <li v-for="scope in pending.scopes" :key="scope">{{ scopeDescriptions[scope] }}</li>
          </ul>

          <p class="mt-4 text-sm">This request expires at {{ expiresAt }}.</p>

          <div class="flex flex-col gap-3 mt-6">
            <form v-for="provider in pending.providers" :key="provider" method="post" :action="`${requestPath}/${provider}`">
              <button type="submit" class="btn btn-primary w-full">Sign in with {{ providerNames[provider] }}</button>
            </form>

            <form method="post" :action="`${requestPath}/cancel`">
              <button type="submit" class="btn btn-ghost w-full">Cancel</button>
            </form>
          </div>
        </template>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import type { AuthorizationProvider, PendingAuthorizationDto, RequestedScope } from '~/types/nativeAuthorizationDto';

const unavailableMessage = "This sign-in request is no longer available. Return to the application and start again."

// The page handle arrives only in the fragment, which a browser never sends to
// a server or puts in a referrer. Nothing else is accepted.
const handoff = /^#request=([A-Za-z0-9_-]{43})$/

const scopeDescriptions: Record<RequestedScope, string> = {
  openid: "Confirm who you are, with an identifier only this application receives.",
  profile: "See your AbandonAuth username. Your username can be the same at every application you use, so applications can recognise it as yours.",
  offline_access: "Keep you signed in for up to 90 days without asking again. You can have ten active sessions with this application; signing in for another ends the least recently created one.",
}

const providerNames: Record<AuthorizationProvider, string> = {
  discord: "Discord",
  github: "GitHub",
  google: "Google",
  steam: "Steam",
}

const state = ref<"loading" | "ready" | "unavailable">("loading")
const pending = ref<PendingAuthorizationDto | null>(null)
const requestPath = ref("")

const expiresAt = computed(() => pending.value ? new Date(pending.value.expires_at).toLocaleTimeString() : "")

onMounted(async () => {
  const handle = handoff.exec(window.location.hash)?.[1]

  if (window.location.hash !== "") {
    window.history.replaceState(null, "", "/authorize")
  }

  if (handle === undefined) {
    state.value = "unavailable"

    return
  }

  requestPath.value = `/api/oauth/authorization/${handle}`

  try {
    pending.value = await $fetch<PendingAuthorizationDto>(requestPath.value)
    state.value = "ready"
  } catch {
    state.value = "unavailable"
  }
})
</script>
