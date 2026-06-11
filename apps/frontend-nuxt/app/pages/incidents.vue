<script lang="ts" setup>
import type { ThreatAlert } from "~/types/types";

definePageMeta({
    middleware: "auth",
});

const { getHistory } = useAlerts();
const { data: incidents, pending } = await getHistory();

if (!incidents.value) {
    incidents.value = [];
}

function formatTimeStamp(val: string) {
    if (!val) return "N/A";
    return new Date(val).toLocaleString();
}
</script>

<template>
    <div class="section">
        <p class="panel-title">Incidents</p>
        <Separator class="primary" />

        <div class="content">
            <div class="table-container">
                <table
                    v-if="incidents && incidents.length > 0"
                    class="incidents-table"
                >
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Source IP</th>
                            <th>Target IP</th>
                            <th>Port</th>
                            <th>Protocol</th>
                            <th>Score</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr
                            v-for="incident in incidents"
                            :key="incident.id || incident.timeStamp"
                        >
                            <td>{{ formatTimeStamp(incident.timeStamp) }}</td>
                            <td>{{ incident.sourceIp }}</td>
                            <td>{{ incident.destinationIp }}</td>
                            <td>{{ incident.destinationPort }}</td>
                            <td>
                                {{ incident.protocol === 6 ? "TCP" : "UDP" }}
                            </td>
                            <td class="score">
                                {{ incident.anomalyScore.toFixed(4) }}
                            </td>
                        </tr>
                    </tbody>
                </table>

                <div v-else-if="pending" class="empty-state">
                    <Icon
                        name="svg-spinners:ring-resize"
                        size="24"
                        class="spinner"
                    />
                    <p>Loading threat history...</p>
                </div>

                <div v-else class="empty-state">
                    <p>No historical incidents found.</p>
                </div>
            </div>
        </div>
    </div>
</template>

<style lang="scss" scoped src="~/assets/scss/pages/incidents.scss"></style>
