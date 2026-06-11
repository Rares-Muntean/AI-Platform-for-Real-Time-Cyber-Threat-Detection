<script lang="ts" setup>
definePageMeta({
    middleware: "auth",
});

const { theme, toggleTheme } = useTheme();
</script>

<template>
    <div class="section">
        <p class="panel-title">Settings</p>
        <Separator class="primary" />

        <div class="content settings-content">
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

            <Separator class="primary settings-separator" />

            <div class="setting">
                <div class="settings-info">
                    <p class="setting-title">Incident Alerts</p>
                    <p class="setting-description">
                        Configure threshold levels and delivery channels for
                        real-time high-severity alerts.
                    </p>
                </div>

                <div class="setting-button-container">
                    <button class="btn ui-size" @click="">
                        <Icon
                            name="material-symbols:notifications-active-rounded"
                            class="icon"
                            size="16"
                        />
                        <p>Edit Rules</p>
                    </button>
                </div>
            </div>

            <Separator class="primary settings-separator" />
        </div>
    </div>
</template>

<style lang="scss" scoped src="~/assets/scss/pages/settings.scss"></style>
