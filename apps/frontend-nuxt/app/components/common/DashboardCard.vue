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
    border: solid 2px $whiteTextDark75;

    padding: 2.6rem 2.2rem;

    background-color: $primaryBackgroundColor;
    box-shadow: 4px 8px 12px rgba($color: #000000, $alpha: 0.1);

    z-index: 1;
}

.title-card {
    font-size: 1.8rem;
}
</style>
