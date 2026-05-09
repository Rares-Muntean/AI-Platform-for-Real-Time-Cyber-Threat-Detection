<script lang="ts" setup></script>

<template>
    <div class="card">
        <slot name="content"></slot>
    </div>
</template>

<style lang="scss" scoped>
.card {
    border-radius: 4px;
    border: solid 2px $whiteText20;

    padding: 1.6rem 1.8rem;
}
</style>
