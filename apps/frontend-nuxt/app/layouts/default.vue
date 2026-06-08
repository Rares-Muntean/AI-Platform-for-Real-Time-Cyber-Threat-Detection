<script lang="ts" setup>
import type { NavGroup } from "~/types/types";
const { user } = useAuth();

const navigationGroups = computed<NavGroup[]>(() => [
    {
        title: "MONITORING",
        items: [
            {
                name: "Dashboard",
                icon: "material-symbols:dashboard-2",
                to: "/dashboard",
            },
            {
                name: "Live Feed",
                icon: "material-symbols:bolt-rounded",
                to: "/live-feed",
            },
            {
                name: "Incidents",
                icon: "material-symbols:shield-rounded",
                to: "/incidents",
            },
        ],
    },
    {
        title: "SYSTEM",
        items: [
            {
                name: "Settings",
                icon: "material-symbols:settings-rounded",
                to: "/settings",
            },
        ],
    },
    {
        title: "ACCOUNT",
        items: [
            {
                name:
                    `${user.value?.firstName} ${user.value?.lastName}` ||
                    "Profile",
                icon: "material-symbols:account-circle",
                to: "/profile",
            },
            {
                name: "Log Out",
                icon: "material-symbols:exit-to-app-rounded",
                to: "/logout",
            },
        ],
    },
]);
</script>

<template>
    <div class="section">
        <RadialGradient
            :position-x="-65"
            :position-y="-20"
            :size="700"
            :opacity="0.5"
        />

        <RadialGradient
            :position-x="68"
            :position-y="0"
            :size="1300"
            :opacity="0.5"
            :right="0"
            :top="0"
        />

        <div class="left-panel">
            <div class="logo-container">
                <div class="logo-wrapper">
                    <img class="logo-icon" src="/images/logo-icon.png" alt="" />
                    <p class="icon-text">VELOX</p>
                </div>
                <Separator />
            </div>

            <div class="sidenav-container">
                <div
                    v-for="group in navigationGroups"
                    :key="group.title"
                    class="nav-group"
                >
                    <p class="nav-title">{{ group.title }}</p>

                    <div class="items">
                        <NuxtLink
                            v-for="item in group.items"
                            :key="item.to"
                            :to="item.to"
                            class="item"
                            active-class="selected"
                        >
                            <Icon :name="item.icon" class="icon" />
                            <p class="item-name">{{ item.name }}</p>
                        </NuxtLink>
                    </div>
                </div>
            </div>
        </div>

        <div class="right-panel">
            <slot />
        </div>
    </div>
</template>

<style lang="scss" scoped src="~/assets/scss/layouts/default.scss"></style>
