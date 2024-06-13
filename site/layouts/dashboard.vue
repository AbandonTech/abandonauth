<template>
    <div class='m-0 p-0 flex bg-base-100'>
      <aside class='sticky top-0 left-0 z-40 min-w-64 h-screen '>
        <div class='h-full overflow-y-auto bg-base-200'>
          <div class='flex items-center pl-2.5 mb-5'>
            <span class='self-center text-xl font-semibold whitespace-nowrap dark:text-white'>AbandonAuth</span>
          </div>
  
          <ul class='space-y-3'>
            <li class="px-4">
              <a href='/' class='no-animation btn btn-primary w-full'>
                <font-awesome-icon :icon="faHouse" class="w-6" />
                <span class='ml-3'>Home</span>
              </a>
            </li>
  
            <li class="px-4">
              <a href='/developer-applications' class='no-animation btn btn-primary w-full'>
                <font-awesome-icon :icon="faUsers" class="w-6" />
                <span class='ml-3'>Developer Applications</span>
              </a>
            </li>
          </ul>
  
          <ul class='pt-4 mt-4 space-y-2 border-t-2 border-primary/20'>
            <li class="px-4">
              <a :href="abandonAuthUrl + '/docs'" target="_blank" class='no-animation btn btn-primary w-full'>
                <font-awesome-icon :icon="faBookOpen" class="w-6" />
                <span class='ml-3'>Api Docs</span>
              </a>
            </li>
          </ul>
  
          <ul class='pt-4 mt-4 space-y-2 border-t-2 border-primary/20'>
            <li class="px-4">
              <button class='no-animation btn btn-primary w-full' @click="handleLogout">
                <font-awesome-icon :icon="faCircleLeft" class="w-6" />
                <span class='ml-3 text-primary-content'>Logout</span>
              </button>
            </li>
          </ul>
  
        </div>
      </aside>
  
      <NuxtPage />
    </div>
  </template>
  
  <script setup lang="ts">
  import { useRouter } from 'vue-router'
  import { faBookOpen, faCircleLeft, faHouse, faUsers } from '@fortawesome/free-solid-svg-icons'
  const config = useRuntimeConfig()
  const router = useRouter()
  const authCookie = useCookie("Authorization")
  
  const { abandonAuthUrl, loginPath } = config.public;
  
  async function handleLogout() {
    authCookie.value = null
    await router.push(loginPath)
  }
  </script>