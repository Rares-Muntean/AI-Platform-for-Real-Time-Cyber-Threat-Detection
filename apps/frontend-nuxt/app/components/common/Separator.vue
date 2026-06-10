<template>
    <div class="separator"></div>
</template>

<script lang="ts" setup></script>

<style lang="scss">
.separator {
    height: 2px;
    background: linear-gradient(
        to right,
        $primaryColor,
        $primaryBackgroundColor
    );
    border-radius: 3px;

    &.primary {
        height: 2px;
        width: 100%;
        border-radius: 3px;
        background: none;
        background-color: $backgroundColorContrast;
    }
}
</style>
