<template>
    <footer id="footer" class="footer h-64 lg:h-full p-10 bg-primary text-primary-content">
        <div class="flex flex-col items-center text-2xl gap-4 mx-auto">
            <div class="flex flex-row gap-3">
                <ClientOnly>
                    <NuxtLink to="https://github.com/AbandonTech/abandonauth" target="_blank"><font-awesome-icon icon="fa-brands fa-github" /></NuxtLink>
                    <NuxtLink to="mailto:info@abandontech.cloud" target="_blank"><font-awesome-icon icon="fa-solid fa-envelope" /></NuxtLink>
                </ClientOnly>
            </div>
            <p>info@abandontech.cloud</p>
        </div>
    </footer>
</template>
