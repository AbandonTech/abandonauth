<template>
    <div class="navbar px-7 h-20 fixed bg-primary">
        <div class="flex-1">
            <NuxtLink to="/"><h1 class="text-2xl">AbandonAuth</h1></NuxtLink>
        </div>

        <div class="flex-none">
            <ul class="menu menu-horizontal text-lg px-1">

                <li><NuxtLink to="/developer-applications" @click="removeClickFocus">Developer Applications</NuxtLink></li>
                <li><NuxtLink to="/docs" @click="removeClickFocus" target="_blank">Docs</NuxtLink></li>
                <li><NuxtLink to="/logout" @click="removeClickFocus">Logout</NuxtLink></li>

            </ul>
        </div>

    </div>
</template>

<script setup>
    function removeClickFocus() {
        // Hack to remove focus/hover effects when clicked elements are permanently focused when clicked
        document.activeElement?.blur();
    }
</script>
