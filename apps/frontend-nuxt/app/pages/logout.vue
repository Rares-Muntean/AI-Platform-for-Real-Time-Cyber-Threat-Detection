<script lang="ts" setup>
definePageMeta({ layout: false, middleware: "auth" });

const { logout } = useAuth();

onMounted(async () => {
    await logout();
    await navigateTo("/signUp");
});
</script>

<template>
    <div></div>
</template>

<style lang="scss" scoped></style>
