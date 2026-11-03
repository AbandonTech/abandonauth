<template>
  <div>
    <dialog class="modal modal-bottom sm:modal-middle" :class="{'modal-open': showAppModal}">
      <div class="modal-box">
        <h3 class="font-bold text-lg">{{ createdApplicationName }}</h3>

        <p class="text-lg mt-2"><span>Application ID: </span><CopyString :content="createdApplicationId"/></p>
        <template v-if="createdApplicationToken">
          <p class="text-lg font-mono mt-2"><span>Token: </span><CopyString class="text-orange-500" :content="createdApplicationToken"/></p>

          <p class="text-xs">Your token will never be visible again!</p>
        </template>
        <p v-else class="text-sm mt-2" data-test="no-credential">A public client has no credential. Register its loopback redirects on the application's page.</p>

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
      <fieldset class="pt-2 flex flex-col gap-2" data-test="client-type">
        <legend class="text-sm">Client type (cannot be changed later)</legend>
        <label v-for="(label, clientType) in clientTypeLabels" :key="clientType" class="flex items-center gap-2">
          <input type="radio" name="client_type" class="radio radio-primary" :value="clientType" v-model="newClientType"/>
          <span>{{ label }}</span>
        </label>
      </fieldset>
      <p v-if="applicationSubmitError" class="text-error text-sm mt-2" data-test="submit-error">{{ applicationSubmitError }}</p>
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
  </div>
</template>

<script setup lang="ts">
import { faPlus } from '@fortawesome/free-solid-svg-icons'
import { clientTypeLabels } from '~/types/developerApplicationDto';
import type { ClientType, CreateDeveloperApplicationDto, DeveloperApplicationDto } from '~/types/developerApplicationDto';

const spinAddButton = ref(false)
const applicationSubmitError = ref("")

const showAppModal = ref(false)
const createdApplicationId = ref("")
const createdApplicationName = ref("")
const createdApplicationToken = ref("")

const { data: applications, refresh } = await useFetch<DeveloperApplicationDto[]>('/api/user/applications', {
  lazy: true,
  headers: useRequestHeaders(['cookie'])
})

const newApplicationName = ref("")
const newClientType = ref<ClientType | "">("")

async function resetApplicationField() {
  spinAddButton.value = false
  newApplicationName.value = ""
  newClientType.value = ""
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

  if (newClientType.value === "") {
    applicationSubmitError.value = "Choose a client type"
    spinAddButton.value = false
    return
  }

  const resp = await $fetch<CreateDeveloperApplicationDto>('/api/developer_application', {
    method: 'POST',
    body: { name: name, client_type: newClientType.value },
    headers: siteRequestHeaders()
  }).catch((err) =>{
    applicationSubmitError.value = err.value.statusCode ? `Error: HTTP ${err.value.statusCode}` : "An unkown error occurred"
    resetApplicationField()
    return null
  })

  if (resp === null) {
    return
  }

  createdApplicationId.value = resp.id
  createdApplicationName.value = resp.name
  createdApplicationToken.value = resp.client_type === "confidential" ? (resp.token ?? "") : ""

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
