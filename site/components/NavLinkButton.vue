<template>
    <a class="no-animation btn btn-primary w-full">
        <div class="flex flex-row items-center w-full">
            <font-awesome-icon :icon="$props.linkIcon" class="text-lg" />
            <span class='ml-4 font-semibold'>{{ $props.title }}</span>
        </div>
    </a>
</template>

<script setup lang="ts">
import type { IconDefinition } from '@fortawesome/fontawesome-svg-core';


defineProps<{
    title: String,
    linkIcon: IconDefinition,
}>()
</script>