<script lang="ts" setup>
definePageMeta({ layout: false });

onMounted(async () => {
    await navigateTo("/signUp");
});
</script>

<template>
    <div class="logout-spinner">
        <!-- <Icon name="line-md:loading-twotone-loop" size="24" />
        <p>Logging you out, please wait...</p> -->
    </div>
</template>

<style lang="scss" scoped>
.logout-spinner {
    display: flex;
    gap: 1rem;
}
</style>
