<template>
  <SignInLayout :status="state === 'loading' ? 'Loading the request...' : ''" :errors="state === 'unavailable' ? [unavailableRequestMessage] : []">
    <template v-if="consent" #sentence>
      <p class="mt-6">{{ consent.application_name }} wants to use your AbandonAuth account to:</p>
    </template>

    <template v-if="consent">
      <ul class="mt-6 list-disc pl-6 space-y-2 max-w-96 mx-auto text-left" data-test="permissions">
        <li v-for="scope in consent.scopes" :key="scope">{{ permissions[scope] }}</li>
      </ul>

      <div class="flex flex-col items-center gap-4 mt-8">
        <form method="post" :action="`${consentPath}/allow`">
          <button type="submit" class="btn btn-primary w-96">Allow</button>
        </form>
        <form method="post" :action="`${consentPath}/cancel`">
          <button type="submit" class="btn btn-ghost w-96">Cancel</button>
        </form>
      </div>
    </template>
  </SignInLayout>
</template>

<script setup lang="ts">
import SignInLayout from '~/components/SignInLayout.vue';
import type { RequestedScope } from '~/types/nativeAuthorizationDto';
import type { NativeConsentDto } from '~/types/nativeConsentDto';
import { millisecondsUntil, takeHandoffHandle, unavailableRequestMessage } from '~/utils/authorizationHandoff';

const permissions: Record<RequestedScope, string> = {
  openid: "Identify you with your AbandonAuth user ID. This ID is the same for every application.",
  profile: "See your AbandonAuth username.",
  offline_access: "Keep you signed in for up to 90 days.",
}

// The exact sets the API can report, so a permission is never left undisclosed
// because the page did not recognise how it was asked for.
const canonicalScopes: RequestedScope[][] = [
  ["openid"],
  ["openid", "profile"],
  ["openid", "offline_access"],
  ["openid", "profile", "offline_access"],
]

const state = ref<"loading" | "ready" | "unavailable">("loading")
const consent = ref<NativeConsentDto | null>(null)
const consentPath = ref("")

let deadline: ReturnType<typeof setTimeout> | undefined
let leaving = false

function becomeUnavailable() {
  consent.value = null
  consentPath.value = ""
  state.value = "unavailable"
}

function hasCanonicalScopes(model: NativeConsentDto): boolean {
  return Array.isArray(model.scopes) && canonicalScopes.some((canonical) =>
    canonical.length === model.scopes.length && canonical.every((scope, index) => scope === model.scopes[index]))
}

onMounted(async () => {
  const handle = takeHandoffHandle("/consent")

  if (handle === undefined) {
    becomeUnavailable()

    return
  }

  const path = `/api/oauth/consent/${handle}`

  try {
    const model = await $fetch<NativeConsentDto>(path)
    const remaining = millisecondsUntil(model.expires_at)

    if (leaving) {
      return
    }

    if (remaining === undefined || typeof model.application_name !== "string" || !hasCanonicalScopes(model)) {
      becomeUnavailable()

      return
    }

    consentPath.value = path
    consent.value = model
    state.value = "ready"
    deadline = setTimeout(becomeUnavailable, remaining)
  } catch {
    becomeUnavailable()
  }
})

onBeforeUnmount(() => {
  leaving = true
  clearTimeout(deadline)
})
</script>
