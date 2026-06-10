<script lang="ts" setup>
const model = defineModel<boolean>();

const props = defineProps<{
    title: string;
    subtitle: string;
}>();
</script>

<template>
    <Transition name="page">
        <div v-if="model" class="modal-container">
            <div @click="model = false" class="background-dim"></div>

            <div class="modal-window">
                <div class="modal-header">
                    <div class="left-side">
                        <div class="icon-content">
                            <slot name="icon">
                                <Icon
                                    name="material-symbols:library-add-rounded"
                                />
                            </slot>
                        </div>

                        <div class="text-content">
                            <p class="modal-title">{{ title }}</p>
                            <p class="modal-subtitle">
                                {{ subtitle }}
                            </p>
                        </div>
                    </div>

                    <Icon
                        @click="model = false"
                        class="icon"
                        name="material-symbols:close-rounded"
                        size="22"
                    />
                </div>

                <Separator class="primary" />

                <div class="modal-content">
                    <slot />
                </div>
            </div>
        </div>
    </Transition>
</template>

<style scoped src="~/assets/scss/general/addDeviceModal.scss"></style>
