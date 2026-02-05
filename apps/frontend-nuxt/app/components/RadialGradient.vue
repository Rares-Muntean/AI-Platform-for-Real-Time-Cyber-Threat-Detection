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

<style lang="scss" src="~/assets/scss/scoped/RadialGradient.scss"></style>
