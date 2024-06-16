<template>
<dialog class="modal modal-bottom sm:modal-middle" :class="{'modal-open': showAppModal}">
  <div class="modal-box">
    <h3 class="font-bold text-lg">{{ createdApplicationName }}</h3>

    <p class="text-lg mt-2"><span>Application ID: </span><CopyString :content="createdApplicationId"/></p>
    <p class="text-lg mt-2"><span>Token: </span><CopyString class="text-orange-500" :content="createdApplicationToken"/></p>

    <p class="text-xs">Your token will never be visible again!</p>
    
    <div class="modal-action">
      <form method="dialog">
        <button class="btn" @click="closeCreateAppModal">Close</button>
      </form>
    </div>
  </div>
</dialog>

  <div class="m-10">
    <h1 class="text-4xl">My Applications</h1>

    <h2 class="mt-10 text-lg">Create New Application</h2>
    <div class="pt-2 w-96">
        <label class="input input-bordered input-ghost flex items-center bg-base-200">
          <input type="text" class="grow bg-inherit" placeholder="Application Name" v-model="newApplicationName" @keydown.enter="createApplication(newApplicationName)"/>
          <font-awesome-icon 
            :icon="faPlus" 
            class="w-5 h-5 text-primary hover:cursor-pointer"
            :class="{ 'animate-spin': spinAddButton }"
            @click="createApplication(newApplicationName)"/>
        </label>
      </div>

    <div class="flex flex-row flex-wrap gap-10 my-10">
      <div v-for="app in applications">
        <!-- Cannot use NuxtLink here as it will fail to load any elements on this page if using back navigation and will not load specified application ID page on click. -->
        <a :href="'/developer-applications/' + app.id" class="card w-96 bg-base-300 shadow-xl hover:scale-110 transition">
          <div class="card-body">
            <h2 class="card-title">{{ app.name }}</h2>
            <button class="text-left">{{ app.id }}</button>
          </div>

        </a>
      </div>
    </div>

  </div>
</template>

<script setup lang="ts">
import { faPlus } from '@fortawesome/free-solid-svg-icons'
import type { CreateDeveloperApplicationDto, DeveloperApplicationDto } from '~/types/developerApplicationDto';

const config = useRuntimeConfig()
const auth = useCookie("Authorization");

const spinAddButton = ref(false)
const applicationSubmitError = ref("")

const showAppModal = ref(false)
const createdApplicationId = ref("")
const createdApplicationName = ref("")
const createdApplicationToken = ref("")

const { data: applications, refresh } = await useFetch<DeveloperApplicationDto[]>(`${config.public.abandonAuthUrl}/user/applications`, {
  lazy: true,
  headers: {
    Authorization: `Bearer ${auth.value}`
  }
})

const newApplicationName = ref("")

async function resetApplicationField() {
  spinAddButton.value = false
  newApplicationName.value = ""
  if (applicationSubmitError.value.length >= 1) {
    setTimeout(() => {
      applicationSubmitError.value = ""
    }, 7000)
  }
}

async function closeCreateAppModal() {
  showAppModal.value = false
  createdApplicationId.value = ""
  createdApplicationName.value = ""
  createdApplicationToken.value = ""
}

async function createApplication(name: string) {
  spinAddButton.value = true

  if (newApplicationName.value.length < 1) {
    applicationSubmitError.value = "Application name cannot be blank"
    return resetApplicationField()
  }

  const resp = await $fetch<CreateDeveloperApplicationDto>(`${config.public.abandonAuthUrl}/developer_application`, {
    method: 'POST',
    body: { name: name },
    headers: {
      Authorization: `Bearer ${auth.value}`
    }
  }).catch((err) =>{
    applicationSubmitError.value = err.value.statusCode ? `Error: HTTP ${err.value.statusCode}` : "An unkown error occurred"
    resetApplicationField()
    return null
  })

  if (resp !== null) {
    createdApplicationId.value = resp.id
    createdApplicationName.value = resp.name
    createdApplicationToken.value = resp.token
  }

  showAppModal.value = true

  
  setTimeout(() => {
    refresh()
    resetApplicationField()
  }, 500)
}

definePageMeta({
  layout: 'dashboard'
})
</script>
