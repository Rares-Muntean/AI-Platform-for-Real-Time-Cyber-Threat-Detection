<script lang="ts" setup>
const props = defineProps<{
    size: number;
    positionX: number;
    positionY: number;
    bottom?: number;
    top?: number;
    left?: number;
    right?: number;
}>();
</script>

<template>
    <div
        class="radial-gradient"
        :style="{
            width: props.size + 'px',
            height: props.size + 'px',
            transform: `translate(${props.positionX}%, ${props.positionY}%)`,
            bottom: props.bottom + 'px',
            top: props.top + 'px',
            left: props.left + 'px',
            right: props.right + 'px',
        }"
    ></div>
</template>

<style lang="scss">
.radial-gradient {
    position: absolute;

    background: radial-gradient(
        circle,
        rgba(71, 188, 246, 0.4) 5%,
        rgba(71, 188, 246, 0.05) 60%,
        transparent 70%
    );

    z-index: 0;
}
</style>
