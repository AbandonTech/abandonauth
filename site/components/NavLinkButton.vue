<template>
    <a class="no-animation btn btn-primary w-full">
        <div class="flex flex-row items-center w-full">
            <font-awesome-icon :icon="$props.linkIcon" class="w-6" />
            <span class='mx-4 text-xl font-semibold text-center flex-grow'>{{ $props.title }}</span>
        </div>
    </a>
</template>

<script setup lang="ts">
import type { IconDefinition } from '@fortawesome/fontawesome-svg-core';


defineProps({
    title: {
        type: String,
        required: true
    },
    linkIcon: {
        type: Object as PropType<IconDefinition>,
        required: true
    }
})
</script>