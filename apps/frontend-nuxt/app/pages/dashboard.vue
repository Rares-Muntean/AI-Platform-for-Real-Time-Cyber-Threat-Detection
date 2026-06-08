<!-- pages/dashboard.vue -->
<script lang="ts" setup>
import type { ThreatAlert } from "~/types/types";

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
</script>

<template>
    <div>
        <h2 class="panel-title">Dashboard</h2>
        <section class="dashboard-section">
            <DashboardCard class="anomaly-history">
                <template #title-card>
                    <p>ANOMALY HISTORY</p>
                </template>
                <template #content>
                    <div class="chart-container">
                        <div class="y-axis">
                            <span v-for="label in yAxisLabels" :key="label">{{
                                label
                            }}</span>
                        </div>
                        <div class="chart-area">
                            <div class="grid-lines">
                                <div class="line" v-for="n in 8" :key="n"></div>
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
</template>

<style lang="scss" scoped src="~/assets/scss/pages/dashboard.scss"></style>
