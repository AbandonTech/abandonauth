<template>
  <SignInLayout :errors="errors">
    <template #sentence>
      <p v-if="applicationName" class="mt-6">{{ applicationName }} wants you to login with AbandonAuth</p>
    </template>

    <div class='flex flex-col items-center gap-4 mt-16 lg:mt-20'>
      <LoginButton v-for="(mark, provider) in providerMarks" :key="provider" v-bind="{ ...mark, ...action(provider) }" />
    </div>
  </SignInLayout>
</template>

<script setup lang="ts">
import LoginButton from '~/components/LoginButton.vue';
import SignInLayout from '~/components/SignInLayout.vue';
import type { AuthorizationProvider } from '~/types/nativeAuthorizationDto';
import { providerMarks } from '~/utils/providerMarks';

defineProps<{
  applicationName?: string,
  errors?: string[],
  action: (provider: AuthorizationProvider) => { redirectUrl: string } | { formAction: string },
}>();
</script>
