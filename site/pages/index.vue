<template>
  <div class="m-10">
    <div class="card w-96 bg-base-300 shadow-xl">
      <div class="card-body">
        <h2 class="card-title">{{ user.username }}</h2>
        <button class="text-left tooltip transition-colors" :data-tip="tooltipMessage" type="button" @click="copyUserIdToClipboard">{{ user.id }}</button>
      </div>
    </div>
  </div>

</template>

<script setup lang="ts">
import type { UserDto } from '~/types/userDto';

const config = useRuntimeConfig()
const auth = useCookie("Authorization");
const tooltipMessage = ref("copy to clipboard")

const { data: user, refresh } = await useFetch<UserDto>(`${config.public.abandonAuthUrl}/me`, {
  lazy: true,
  headers: {
    Authorization: `Bearer ${auth.value}`
  }
})

async function copyUserIdToClipboard(event) {
  navigator.clipboard.writeText(user.value.id);
  const element = event.target;
  element.classList.add("text-emerald-500");
  tooltipMessage.value = "copied!"
  setTimeout(() => {
    element.classList.remove("text-emerald-500")
    tooltipMessage.value = "copy to clipboard"
  }, 1500)

}

definePageMeta({
  layout: 'dashboard'
})
</script>