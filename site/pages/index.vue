<template>
  <div class="m-10">
    <div class="card w-96 bg-base-300 shadow-xl">
      <div class="card-body">
        <h2 class="card-title">{{ user.username }}</h2>
        <CopyString :content="user.id" />
      </div>
    </div>
  </div>

</template>

<script setup lang="ts">
import type { UserDto } from '~/types/userDto';

const config = useRuntimeConfig()
const auth = useCookie("Authorization");

const { data: user } = await useFetch<UserDto>(`${config.public.abandonAuthUrl}/me`, {
  lazy: true,
  headers: {
    Authorization: `Bearer ${auth.value}`
  }
})

definePageMeta({
  layout: 'dashboard'
})
</script>