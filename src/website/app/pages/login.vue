<template>
  <ProviderSignIn :application-name="applicationId" :errors="errors" :action="providerLink" />
</template>

<script setup lang="ts">
import ProviderSignIn from '~/components/ProviderSignIn.vue';
import type { AuthorizationProvider } from '~/types/nativeAuthorizationDto';
import { providerLoginUrl } from '~/utils/providerLogin';

const route = useRoute();

const applicationId = String(route.query.application_id ?? "");
const callbackUri = String(route.query.callback_uri ?? "");

const errors: string[] = [];

if (!applicationId) {
  errors.push("application_id is required")
}

if (!callbackUri) {
  errors.push("callback_uri is required")
}

function providerLink(provider: AuthorizationProvider) {
  return { redirectUrl: providerLoginUrl(provider, applicationId, callbackUri) }
}
</script>
