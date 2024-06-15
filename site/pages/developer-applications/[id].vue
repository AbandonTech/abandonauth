<template>
    <div class="mx-auto my-10">
        <h1 class="text-4xl">{{ application.name }}</h1>
        <CopyString :content="application.id" />

        <h2 class="text-2xl mt-10 text-center">Callback Uris</h2>
    <div v-for="uri in application.callback_uris" class="mt-5">
        <div class="p-4 mx-auto rounded-lg text-center w-56 bg-base-300 shadow-xl">
          <div>
            <p>{{ uri }}</p>
          </div>

        </div>
      </div>
    </div>
</template>

<script setup lang="ts">
import type { DeveloperApplicationDto } from '~/types/developerApplicationDto';

const config = useRuntimeConfig()
const auth = useCookie("Authorization");
const route = useRoute()

const application_id = route.params.id

const { data: application } = await useFetch<DeveloperApplicationDto>(`${config.public.abandonAuthUrl}/developer_application/${application_id}`, {
  lazy: true,
  headers: {
    Authorization: `Bearer ${auth.value}`
  }
})

definePageMeta({
  layout: 'dashboard'
})
</script>