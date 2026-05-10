<script lang="ts" setup>
const props = withDefaults(
    defineProps<{
        size: number;
        positionX: number;
        positionY: number;
        src?: string;
        bottom?: number;
        top?: number;
        left?: number;
        right?: number;
        opacity?: number;
    }>(),
    {
        opacity: 0.8,
        src: "/images/glow-primary.png",
    },
);
</script>

<template>
    <div
        class="glow-container"
        :style="{
            width: size + 'px',
            height: size + 'px',
            transform: `translate(${positionX}%, ${positionY}%)`,
            bottom: bottom + 'px',
            top: top + 'px',
            left: left + 'px',
            right: right + 'px',
            opacity: opacity,
        }"
    >
        <img :src="src" class="glow-image" alt="" />
    </div>
</template>

<style lang="scss" scoped>
.glow-container {
    position: absolute;
    pointer-events: none;
    z-index: 0;
    display: flex;
    align-items: center;
    justify-content: center;
}

.glow-image {
    width: 100%;
    height: 100%;
    object-fit: contain;
    image-rendering: -webkit-optimize-contrast;
}
</style>
