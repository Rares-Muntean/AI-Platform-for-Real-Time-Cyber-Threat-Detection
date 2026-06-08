<script lang="ts" setup>
import type { DisplayField, NavGroup } from "~/types/types";

// REFS + BASE MOUNTS
const { getHistory, getLast } = useAlerts();
const { data: alerts, refresh, pending } = await getLast();

let interval: any;
onMounted(() => {
    interval = setInterval(() => {
        refresh();
    }, 3000);
});

onUnmounted(() => {
    clearInterval(interval);
});

watch(
    () => alerts.value,
    (newVal) => {
        console.log("Data retrieved: ", newVal);
    },
);

const yAxisLabels = [70, 60, 50, 40, 30, 20, 10, 0];
const displayFields: DisplayField[] = [
    { label: "Source IP", key: "sourceIp" },
    { label: "Target IP", key: "destinationIp" },
    { label: "Protocol", key: "protocol" },
    { label: "Port", key: "destinationPort" },
    { label: "Total Packets", key: "totalPackets" },
    {
        label: "Anomaly Score",
        key: "anomalyScore",
        format: (val: number) => (Math.floor(val * 1000) / 1000).toFixed(3),
    },
];

const activeTab = ref("Dashboard");
const navigationGroups: NavGroup[] = [
    {
        title: "MONITORING",
        items: [
            {
                name: "Dashboard",
                icon: "material-symbols:dashboard-2",
                value: "Dashboard",
            },
            {
                name: "Live Feed",
                icon: "material-symbols:bolt-rounded",
                value: "Live Feed",
            },
            {
                name: "Incidents",
                icon: "material-symbols:shield-rounded",
                value: "Incidents",
            },
        ],
    },
    {
        title: "SYSTEM",
        items: [
            {
                name: "Settings",
                icon: "material-symbols:settings-rounded",
                value: "Settings",
            },
            {
                name: "Night Mode",
                icon: "material-symbols:partly-cloudy-night-rounded",
                value: "Night Mode",
            },
        ],
    },
    {
        title: "ACCOUNT",
        items: [
            {
                name: "Ion Popescu",
                icon: "material-symbols:account-circle",
                value: "Profile",
            },
            {
                name: "Log Out",
                icon: "material-symbols:exit-to-app-rounded",
                value: "Log Out",
            },
        ],
    },
];

// FUNCTIONS
const formatTimeStamp = (val: string) => {
    if (!val) return "N/A";

    const date = new Date(val);
    return date.toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
    });
};

const toggleActiveTab = (pageName: string) => {
    if (activeTab.value === pageName) {
        return;
    } else {
        activeTab.value = pageName;
    }

    console.log(activeTab.value);
};
</script>

<template>
    <section class="section">
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
                        <div
                            v-for="item in group.items"
                            :key="item.value"
                            class="item"
                            :class="{ selected: activeTab === item.value }"
                            @click="toggleActiveTab(item.value)"
                        >
                            <Icon :name="item.icon" class="icon" />
                            <p class="item-name">{{ item.name }}</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="right-panel">
            <h2 class="panel-title">Dashboard</h2>
            <section class="dashboard-section">
                <DashboardCard class="anomaly-history">
                    <template #title-card>
                        <p>ANOMALY HISTORY</p>
                    </template>
                    <template #content>
                        <div class="chart-container">
                            <div class="y-axis">
                                <span
                                    v-for="label in yAxisLabels"
                                    :key="label"
                                    >{{ label }}</span
                                >
                            </div>

                            <div class="chart-area">
                                <div class="grid-lines">
                                    <div
                                        class="line"
                                        v-for="n in 8"
                                        :key="n"
                                    ></div>
                                </div>
                            </div>
                        </div>
                    </template>
                </DashboardCard>

                <DashboardCard class="alert-count">
                    <template #title-card>
                        <p>ALERT COUNT</p>
                    </template>
                    <template #content> </template>
                </DashboardCard>

                <DashboardCard class="last-alert">
                    <template #title-card>
                        <div class="top-card">
                            <p>LAST ALERT</p>
                            <p v-if="alerts">
                                {{ formatTimeStamp(alerts?.timeStamp) }}
                            </p>
                        </div>
                    </template>

                    <template #content>
                        <div v-if="alerts" class="alert-info">
                            <div
                                v-for="field in displayFields"
                                :key="field.key"
                                class="info-item"
                            >
                                <p class="info-name">{{ field.label }}</p>
                                <p>
                                    {{
                                        field.format
                                            ? field.format(alerts[field.key])
                                            : alerts[field.key]
                                    }}
                                </p>
                            </div>
                        </div>

                        <div v-else-if="pending" class="empty-state">
                            <p>Syncing with server...</p>
                        </div>

                        <div v-else class="empty-state">
                            <p>No threats detected.</p>
                        </div>
                    </template>
                </DashboardCard>
            </section>
        </div>
    </section>
</template>

<style lang="scss" scoped src="~/assets/scss/pages/UserDashboard.scss"></style>
