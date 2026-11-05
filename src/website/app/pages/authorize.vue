<template>
  <ProviderSignIn v-if="selection" :application-name="selection.application_name" :action="providerForm" />
  <SignInLayout v-else :status="state === 'loading' ? 'Loading the request...' : ''" :errors="state === 'unavailable' ? [unavailableRequestMessage] : []" />
</template>

<script setup lang="ts">
import ProviderSignIn from '~/components/ProviderSignIn.vue';
import SignInLayout from '~/components/SignInLayout.vue';
import type { AuthorizationProvider, ProviderSelectionDto } from '~/types/nativeAuthorizationDto';
import { millisecondsUntil, takeHandoffHandle, unavailableRequestMessage } from '~/utils/authorizationHandoff';
import { providerMarks } from '~/utils/providerMarks';

const state = ref<"loading" | "ready" | "unavailable">("loading")
const selection = ref<ProviderSelectionDto | null>(null)
const requestPath = ref("")

let deadline: ReturnType<typeof setTimeout> | undefined
let leaving = false

function providerForm(provider: AuthorizationProvider) {
  return { formAction: `${requestPath.value}/${provider}` }
}

function becomeUnavailable() {
  selection.value = null
  requestPath.value = ""
  state.value = "unavailable"
}

function offersEveryProvider(model: ProviderSelectionDto): boolean {
  const offered = Object.keys(providerMarks)

  return Array.isArray(model.providers) && model.providers.length === offered.length
    && model.providers.every((provider, index) => provider === offered[index])
}

onMounted(async () => {
  const handle = takeHandoffHandle("/authorize")

  if (handle === undefined) {
    becomeUnavailable()

    return
  }

  const path = `/api/oauth/authorization/${handle}`

  try {
    const model = await $fetch<ProviderSelectionDto>(path)
    const remaining = millisecondsUntil(model.expires_at)

    if (leaving) {
      return
    }

    if (remaining === undefined || typeof model.application_name !== "string" || !offersEveryProvider(model)) {
      becomeUnavailable()

      return
    }

    requestPath.value = path
    selection.value = model
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
