<template>
  <div v-if="errors.length > 0" class="w-96 absolute right-0 mr-8">
    <div v-for="message in errors" :key="message" role="alert" class="alert alert-error mt-4">
      <svg xmlns="http://www.w3.org/2000/svg" class="stroke-current shrink-0 h-6 w-6" fill="none" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
      <span>{{ message }}</span>
    </div>
  </div>

  <div class='min-h-screen min-w-screen flex lg:items-center lg:justify-center'>
    <div class='flex flex-col text-center px-8 lg:flex-row lg:rounded-xl lg:text-left'>
      <div class='my-2 lg:mx-40 lg:my-auto'>
        <div class="text-center">
          <h1 class='select-none basis-1/4 text-4xl font-bold text-gray-900 dark:text-gray-100 md:text-5xl lg:text-6xl'>
            AbandonAuth
          </h1>
          <p v-if="status" class="mt-6" data-test="status">{{ status }}</p>
          <slot name="sentence" />
        </div>

        <slot />
      </div>

      <div>
        <img src="/img/atLogoColor.svg" class="hidden lg:block w-full lg:w-[30rem]" alt="AbandonTech" />
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
withDefaults(defineProps<{
  errors?: string[],
  status?: string,
}>(), {
  errors: () => [],
  status: "",
});
</script>
