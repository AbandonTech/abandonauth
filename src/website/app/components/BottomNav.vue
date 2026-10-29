<template>
    <div class="btm-nav border-t border-primary border-opacity-50">
        <ClientOnly>
            <NuxtLink to="/" class="text-primary h-5/6 border-r">
                <font-awesome-icon icon="fa-solid fa-house"></font-awesome-icon>
            </NuxtLink>

            <NuxtLink to="/projects" class="text-primary h-5/6 border-r">
                <font-awesome-icon icon="fa-solid fa-rocket"></font-awesome-icon>
            </NuxtLink>

            <NuxtLink to="/about" class="text-primary">
                <font-awesome-icon icon="fa-solid fa-briefcase"></font-awesome-icon>
            </NuxtLink>
        </ClientOnly>
    </div>
</template>
