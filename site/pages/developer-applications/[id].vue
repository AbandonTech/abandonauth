<template>
  <dialog id="deleteAppModal" class="modal modal-bottom sm:modal-middle" :class="{'modal-open': showAppModal}">
    <div class="modal-box">
      <h3 class="font-bold text-lg">{{ application?.name }}</h3>

      <p class="text-lg"><span>Application ID: </span><span>{{ application?.id }}</span></p>
      <p class="text-lg mt-4">Permanently Delete Application <span class="text-orange-500">{{ application?.name }}</span>?</p>
      <div class="flex flex-row w-full gap-10 mt-4">
        <button class="btn btn-warning w-28" @click="deleteDeveloperApplication">Yes</button>
        <button class="btn btn-error w-28" @click="closeDeleteAppModal">No</button>
      </div>
    </div>
  </dialog>

  <dialog id="resetTokenModal" class="modal modal-bottom sm:modal-middle" :class="{'modal-open': showResetTokenModal}">
    <div class="modal-box">
      <h3 class="font-bold text-lg">{{ application?.name }}</h3>

      <p class="text-lg"><span>Application ID: </span><span>{{ application?.id }}</span></p>
      <p class="text-lg mt-4">Destroy And Reset Existing Token For Application <span class="text-orange-500">{{ application?.name }}</span>?</p>
      <div class="flex flex-row w-full gap-10 mt-4">
        <button class="btn btn-warning w-28" @click="resetDeveloperApplicationToken">Yes</button>
        <button class="btn btn-error w-28" @click="closeResetTokenAppModal">No</button>
      </div>
    </div>
  </dialog>

  <dialog id="newTokenModal" class="modal modal-bottom sm:modal-middle" :class="{'modal-open': showNewTokenModal}">
    <div class="modal-box">
      <h3 class="font-bold text-lg">{{ application?.name }}</h3>

      <p class="text-lg mt-2"><span>Application ID: </span><CopyString :content="application?.id"/></p>
      <p class="text-lg mt-2"><span>Token: </span><CopyString class="text-orange-500" :content="newToken"/></p>

      <p class="text-xs">Your token will never be visible again!</p>

      <div class="modal-action">
        <form method="dialog">
          <button class="btn" @click="closeNewTokenModal">Close</button>
        </form>
      </div>
    </div>
  </dialog>

    <div class="mx-auto my-10">
      <div class="flex flex-col">
        <h1 class="text-4xl">{{ application?.name }}</h1>
        <CopyString class="mt-4" :content="application?.id" />

        <button class="btn btn-warning mt-4" @click="openResetTokenModal">Reset Token</button>

        <button class="btn btn-error mt-4" @click="openDeleteAppModal">Delete Application</button>
      </div>

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
import type { CreateDeveloperApplicationDto, DeveloperApplicationDto, DeveloperApplicationUpdateCallbackDto } from '~/types/developerApplicationDto';
import { faPlus, faTrash } from '@fortawesome/free-solid-svg-icons'

const config = useRuntimeConfig()
const auth = useCookie("Authorization");
const route = useRoute()
const router = useRouter()

const showAppModal = ref(false)
const showResetTokenModal = ref(false)
const newToken = ref("*****")

const showNewTokenModal = ref(false)

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

async function closeDeleteAppModal() {
  showAppModal.value = false
}

async function openDeleteAppModal() {
  showAppModal.value = true
}

async function openResetTokenModal() {
  showResetTokenModal.value = true
}

async function closeResetTokenAppModal() {
  showResetTokenModal.value = false
}

async function closeNewTokenModal() {
  showNewTokenModal.value = false
  newToken.value = "*****"
}

async function resetDeveloperApplicationToken() {
  let resp = await $fetch<CreateDeveloperApplicationDto>(`${config.public.abandonAuthUrl}/developer_application/${application_id}/reset_token`, {
      method: "patch",
      headers: {
        Authorization: `Bearer ${auth.value}`
      },
    }).catch((err) => {
      closeDeleteAppModal()
      return null
    })

    if (resp !== null) {
      closeResetTokenAppModal()
      setTimeout(() => {
        newToken.value = resp.token
        showNewTokenModal.value = true
      }, 500)
    }
}

async function deleteDeveloperApplication() {
  await $fetch<DeveloperApplicationUpdateCallbackDto>(`${config.public.abandonAuthUrl}/developer_application/${application_id}`, {
      method: "DELETE",
      headers: {
        Authorization: `Bearer ${auth.value}`
      },
    }).catch((err) => {
      closeDeleteAppModal()
    })

    setTimeout(() => {
      router.push("/developer-applications")
    }, 500)
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
