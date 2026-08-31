<template>
  <div class="m-10">
    <div class="card w-96 bg-base-300 shadow-xl">
      <div class="card-body">
        <h2 class="card-title">{{ user?.username ?? "Failed To Fetch User" }}</h2>
        <CopyString :content="user?.id" />
      </div>
    </div>
  </div>

</template>

<script setup lang="ts">
import type { UserDto } from '~/types/userDto';

const { data: user } = await useFetch<UserDto>(currentUserPath, {
  lazy: true,
  headers: useRequestHeaders(['cookie'])
})

definePageMeta({
  layout: 'dashboard'
})
</script>
