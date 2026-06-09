<script setup lang="ts">
const { theme } = useTheme();

useHead({
    htmlAttrs: {
        "data-theme": theme,
    },
});
</script>

<template>
    <NuxtLayout>
        <NuxtPage />
    </NuxtLayout>
</template>
