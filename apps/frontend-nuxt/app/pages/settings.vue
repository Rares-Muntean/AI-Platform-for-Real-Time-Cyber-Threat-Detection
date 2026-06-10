<script lang="ts" setup>
definePageMeta({
    middleware: "auth",
});

const { theme, toggleTheme } = useTheme();
</script>

<template>
    <div class="section">
        <p class="panel-title">Settings</p>
        <section class="settings-section">
            <div class="setting">
                <div class="settings-info">
                    <p class="setting-title">
                        {{ theme === "dark" ? "Light" : "Dark" }} Mode
                    </p>
                    <p class="setting-description">
                        Toggle between the light and dark interface themes.
                    </p>
                </div>

                <div class="setting-button-container">
                    <button class="btn ui-size" @click="toggleTheme">
                        <Icon
                            :name="
                                theme === 'dark'
                                    ? 'material-symbols:wb-sunny-rounded'
                                    : 'material-symbols:partly-cloudy-night-rounded'
                            "
                            class="icon"
                            size="16"
                        />
                        <p>Apply</p>
                    </button>
                </div>
            </div>

            <Separator class="primary" />
        </section>
    </div>
</template>

<style lang="scss" scoped src="~/assets/scss/pages/settings.scss"></style>
