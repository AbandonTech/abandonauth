<template>
    <div class="mx-auto my-10">
        <h1 class="text-4xl">{{ application?.name }}</h1>
        <CopyString :content="application?.id" />

      <h2 class="text-2xl mt-10">Callback Uris</h2>

      <ul class="flex flex-col w-64 gap-2 py-4">
        <li v-for="uri in application?.callback_uris" :key="uri" class="w-fill mr-10 join">
          <span class="flex card justify-center items-center bg-base-300 rounded-xl w-full join-item">{{ uri }}</span>
            <button type="button" title="delete-button" class="btn btn-error join-item" @click="removeCallbackUri(uri)">
                <font-awesome-icon :icon="faTrash" class="w-4 h-4 opacity-70  hover:cursor-pointer"/>
            </button>
        </li>
    </ul>
    </div>
</template>

<script setup lang="ts">
import type { DeveloperApplicationDto, DeveloperApplicationUpdateCallbackDto } from '~/types/developerApplicationDto';
import { faTrash } from '@fortawesome/free-solid-svg-icons'

const config = useRuntimeConfig()
const auth = useCookie("Authorization");
const route = useRoute()

const application_id = route.params.id

const { data: application, refresh } = await useFetch<DeveloperApplicationDto>(`${config.public.abandonAuthUrl}/developer_application/${application_id}`, {
  lazy: true,
  headers: {
    Authorization: `Bearer ${auth.value}`
  }
})



async function submitNewCallbackUris() {
  console.log()
  if (application.value?.callback_uris !== undefined){
    await $fetch<DeveloperApplicationUpdateCallbackDto>(`${config.public.abandonAuthUrl}/developer_application/${application_id}/callback_uris`, {
      method: "patch",
      headers: {
        Authorization: `Bearer ${auth.value}`
      },
      body: application.value.callback_uris
    })

    setTimeout(() => {
    refresh()
  }, 500)
    
  }
}

async function removeCallbackUri(uri: String) {
  if (application.value?.callback_uris !== undefined) {
    application.value.callback_uris = application.value.callback_uris.filter(elem => elem !== uri)
    await submitNewCallbackUris()
  }
}

definePageMeta({
  layout: 'dashboard'
})
</script>