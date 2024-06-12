<template>
    <a :href="$props.redirectUrl" class='btn btn-lg w-96 px-16 btn-primary'>
        <div class="flex flex-row items-center w-full">
            <svg :viewBox="$props.svgViewbox" fill="none" xmlns="http://www.w3.org/2000/svg" class="w-10 h-10 text-white" height="1em" width="1em">
                <path :d="$props.svgPathData" fill="#F7F7F7" />
            </svg>
            <span class='mx-4 text-xl font-semibold text-center text-white flex-grow'> Login with {{ $props.title }}</span>
        </div>
    </a>
</template>

<script setup lang="ts">
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
    }
})
</script>