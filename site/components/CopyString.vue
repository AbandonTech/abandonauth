<template>
    <button class="text-left tooltip transition-colors" :data-tip="tooltipMessage" type="button" @click="copyUserIdToClipboard">{{ $props.content }}</button>
</template>

<script setup lang="ts">

const initialTooltip = "copy to clipboard";

const tooltipMessage = ref(initialTooltip);
const highlightColor = "text-emerald-500";

const props = defineProps<{
    content?: string,
}>()

async function copyUserIdToClipboard(event) {
  let copyContent = props.content !== undefined ? props.content : "Id failed to load"
  const element = event.target;

  navigator.clipboard.writeText(copyContent);
  element.classList.add(highlightColor);

  tooltipMessage.value = "copied!"

  setTimeout(() => {
    element.classList.remove(highlightColor)
    tooltipMessage.value = initialTooltip
  }, 1500)

}

</script>
