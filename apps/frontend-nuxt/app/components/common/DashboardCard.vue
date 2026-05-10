<script lang="ts" setup></script>

<template>
    <div class="card">
        <div class="title-card">
            <slot name="title-card"></slot>
        </div>
        <slot name="content"></slot>
    </div>
</template>

<style lang="scss" scoped>
.card {
    display: flex;
    flex-direction: column;
    gap: 2rem;

    border-radius: 4px;
    border: solid 2px $whiteText20;

    padding: 2.6rem 2.2rem;

    background-color: #202020;
    box-shadow: 4px 8px 12px rgba($color: #000000, $alpha: 0.15);
}

.title-card {
    font-size: 1.8rem;
    font-weight: 400;
}
</style>
