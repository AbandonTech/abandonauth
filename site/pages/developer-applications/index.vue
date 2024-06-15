<template>
  <div class="m-10">
    <h1 class="text-4xl">My Applications</h1>

    <div class="flex flex-row flex-wrap gap-10">
      <div v-for="app in applications" class="mt-10">
        <NuxtLink :to="'/developer-applications/' + app.id" class="card w-96 bg-base-300 shadow-xl hover:scale-110 transition">
          <div class="card-body">
            <h2 class="card-title">{{ app.name }}</h2>
            <button class="text-left">{{ app.id }}</button>
          </div>

        </NuxtLink>
      </div>
    </div>

  </div>
</template>

<script setup lang="ts">
import type { DeveloperApplicationDto } from '~/types/developerApplicationDto';

const config = useRuntimeConfig()
const auth = useCookie("Authorization");

const { data: applications, refresh } = await useFetch<DeveloperApplicationDto[]>(`${config.public.abandonAuthUrl}/user/applications`, {
  lazy: true,
  headers: {
    Authorization: `Bearer ${auth.value}`
  }
})

definePageMeta({
  layout: 'dashboard'
})
</script>
