<template>
    <a :href="$props.redirectUrl + `&state=${config.public.abandonAuthApplicationId},${loginCallbackUri}`" :class="'w-96 py-2 px-8 hover:opacity-80 transition-opacity duration-300 rounded-lg ' + $props.bgColorClass">
        <div class="flex flex-row items-center w-full">
            <svg :viewBox="$props.svgViewbox" fill="none" xmlns="http://www.w3.org/2000/svg" class="w-10 h-10 text-white" height="1em" width="1em">
                <path :d="$props.svgPathData" fill="#F7F7F7" />
            </svg>
            <span class='ml-4 text-xl font-semibold flex-grow'> Login with {{ $props.title }}</span>
        </div>
    </a>
</template>

<script setup lang="ts">
const config = useRuntimeConfig();

const loginCallbackUri = `${config.public.abandonAuthUrl}/ui`

defineProps({
    title: {
        type: String,
        required: true
    },
    redirectUrl: {
        type: String,
        required: true
    },
    svgPathData: {
        type: String,
        required: true
    },
    svgViewbox: {
        type: String,
        required: true
    },
    bgColorClass: {
        type: String,
        required: true
    }
})
</script>