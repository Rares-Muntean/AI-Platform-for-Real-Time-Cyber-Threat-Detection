<script lang="ts" setup>
import { useSignalR } from "~/composables/SignalR";
import type { ThreatAlert } from "~/types/types";

definePageMeta({
    middleware: "auth",
});

const store = useAlertsStore();
const { startConnection, onRecieveAlert, stopConnection } = useSignalR();
const liveAlerts = computed(() => store.recentAlerts);

function formatTimeStamp(val: string) {
    if (!val) return "N/A";
    const date = new Date(val);
    return date.toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
    });
}

onMounted(async () => {
    await store.fetchRecent();
    startConnection();

    onRecieveAlert((newAlert) => {
        store.handleIncomingAlert(newAlert);
    });
});

onBeforeUnmount(() => {
    stopConnection();
});
</script>

<template>
    <div class="section">
        <p class="panel-title">Live Feed</p>
        <Separator class="primary" />

        <div class="content">
            <div class="feed-container">
                <div
                    v-for="alert in liveAlerts"
                    :key="alert.id || alert.timeStamp"
                    class="feed-row animated-slide-in"
                >
                    <span class="feed-time"
                        >[{{ formatTimeStamp(alert.timeStamp) }}]</span
                    >
                    <span class="feed-badge"> LOGGED </span>
                    <span class="feed-text">
                        Suspicious connection detected from
                        <span class="info">{{ alert.sourceIp }}</span>
                        targeting local port
                        <span class="info">{{ alert.destinationPort }}</span
                        >. Anomaly Score:
                        <span class="score">{{
                            alert.anomalyScore.toFixed(4)
                        }}</span>
                    </span>
                </div>

                <div
                    v-if="liveAlerts && liveAlerts.length === 0"
                    class="empty-feed"
                >
                    <Icon
                        name="svg-spinners:pulse-ring"
                        size="26"
                        class="spinner"
                    />
                    <p>Listening for incoming security events...</p>
                </div>
            </div>
        </div>
    </div>
</template>

<style lang="scss" scoped src="~/assets/scss/pages/liveFeed.scss"></style>
