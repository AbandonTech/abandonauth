<template>
    <div class="mx-auto my-10">
        <h1 class="text-4xl">{{ application?.name }}</h1>
        <CopyString :content="application?.id" />

        <h2 class="mt-10 text-lg  ">Add Callback Uri</h2>
        <div class="pt-2 w-96">
          <label class="input input-bordered input-ghost flex items-center bg-base-200">
            <input type="text" class="grow bg-inherit" placeholder="New Callback Uri" v-model="newCallbackUriName" @keydown.enter="addCallbackUri(newCallbackUriName)"/>
            <font-awesome-icon 
              :icon="faPlus" 
              class="w-5 h-5 text-primary hover:cursor-pointer"
              :class="{ 'animate-spin': spinAddButton }"
              @click="addCallbackUri(newCallbackUriName)"/>
          </label>
        </div>

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
import { faPlus, faTrash } from '@fortawesome/free-solid-svg-icons'

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

const spinAddButton = ref(false)
const newCallbackUriName = ref("")

async function resetCallbackUriField() {
  spinAddButton.value = false
  newCallbackUriName.value = ""
}

async function submitNewCallbackUris(newUris: string[]) {
  if (application.value?.callback_uris !== undefined){
    await $fetch<DeveloperApplicationUpdateCallbackDto>(`${config.public.abandonAuthUrl}/developer_application/${application_id}/callback_uris`, {
      method: "patch",
      headers: {
        Authorization: `Bearer ${auth.value}`
      },
      body: newUris
    })
  }
}

async function addCallbackUri(uri: string) {
  if (application.value?.callback_uris !== undefined) {
    spinAddButton.value = true

    let newUris = [...application.value.callback_uris]
    newUris.push(uri)

    await submitNewCallbackUris(newUris)

    setTimeout(() => {
      refresh()
      resetCallbackUriField()
    }, 500)
  }
}

async function removeCallbackUri(uri: string) {
  if (application.value?.callback_uris !== undefined) {
    let newUris = application.value.callback_uris.filter(elem => elem !== uri)
    await submitNewCallbackUris(newUris)
    setTimeout(() => {
      refresh()
    }, 500)
  }
}

definePageMeta({
  layout: 'dashboard'
})
</script>