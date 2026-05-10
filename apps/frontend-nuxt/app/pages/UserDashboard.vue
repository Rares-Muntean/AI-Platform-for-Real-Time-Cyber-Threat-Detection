<script lang="ts" setup>
import type { ThreatAlert } from "~/models/threatAlert";

const { getHistory, getLast } = useAlerts();
const { data: alerts, refresh, pending } = await getLast();

let interval: any;
const yAxisLabels = [70, 60, 50, 40, 30, 20, 10, 0];

interface DisplayField {
    label: string;
    key: keyof ThreatAlert;
    format?: (val: any) => string;
}

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

function formatTimeStamp(val: string) {
    if (!val) return "N/A";

    const date = new Date(val);
    return date.toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
    });
}

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
</script>

<template>
    <section class="section">
        <div class="left-panel">
            <div class="logo-container">
                <div class="logo-wrapper">
                    <img class="logo-icon" src="/images/logo-icon.png" alt="" />
                    <p class="icon-text">VELOX</p>
                </div>
                <Separator />
            </div>

            <div class="sidenav-container">
                <div class="nav-group">
                    <p class="nav-title">MONITORING</p>
                    <div class="items">
                        <div class="item selected">
                            <Icon
                                name="material-symbols:dashboard-2"
                                class="icon"
                            />
                            <p class="item-name">Dashboard</p>
                        </div>

                        <div class="item">
                            <Icon
                                name="material-symbols:bolt-rounded"
                                class="icon"
                            />
                            <p class="item-name">Live Feed</p>
                        </div>

                        <div class="item">
                            <Icon
                                name="material-symbols:shield-rounded"
                                class="icon"
                            />
                            <p class="item-name">Incidents</p>
                        </div>
                    </div>
                </div>

                <div class="nav-group">
                    <p class="nav-title">SYSTEM</p>
                    <div class="items">
                        <div class="item">
                            <Icon
                                name="material-symbols:settings-rounded"
                                class="icon"
                            />
                            <p class="item-name">Settings</p>
                        </div>

                        <div class="item">
                            <Icon
                                name="material-symbols:partly-cloudy-night-rounded"
                                class="icon"
                            />
                            <p class="item-name">Night Mode</p>
                        </div>
                    </div>
                </div>

                <div class="nav-group">
                    <p class="nav-title">ACCOUNT</p>
                    <div class="items">
                        <div class="item">
                            <Icon
                                name="material-symbols:account-circle"
                                class="icon"
                            />
                            <p class="item-name">Ion Popescu</p>
                        </div>

                        <div class="item">
                            <Icon
                                name="material-symbols:exit-to-app-rounded"
                                class="icon"
                            />
                            <p class="item-name">Log Out</p>
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
