<template>
    <div class='m-0 p-0 flex bg-base-100'>
      <aside class='sticky top-0 left-0 z-40 min-w-64 h-screen '>
        <div class='h-full overflow-y-auto bg-base-200'>
          <div class='flex items-center pl-2.5 mb-5'>
            <h3 class='text-2xl p-2 whitespace-nowrap text-center w-full dark:text-white'>AbandonAuth</h3>
          </div>

          <ul class='space-y-3'>

            <li class="px-7">
              <NavLinkButton title="Home" href="/" :linkIcon="faHouse" />
            </li>

            <li class="px-7">
              <NavLinkButton title="Applications" href="/developer-applications" :linkIcon="faUsers" />
            </li>

          </ul>

          <ul class='pt-4 mt-4 space-y-2 border-t-2 border-primary/20'>
            <li class="px-7">
              <NavLinkButton title="Documentation" :href="abandonAuthUrl + '/docs'" :linkIcon="faBookOpen" target="_blank" />
            </li>
          </ul>

          <ul class='pt-4 mt-4 space-y-2 border-t-2 border-primary/20'>
            <li class="px-7">
              <button class='no-animation btn btn-primary w-full' @click="handleLogout">
                <div class="flex flex-row items-center w-full">
                  <font-awesome-icon :icon="faCircleLeft" class="text-lg" />
                  <span class='ml-4'>Logout</span>
                </div>
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
