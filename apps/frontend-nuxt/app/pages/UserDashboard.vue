<script lang="ts" setup>
const { getHistory } = useAlerts();
const { data: alerts, refresh, pending } = await getHistory();

let interval: any;
const yAxisLabels = [70, 60, 50, 40, 30, 20, 10, 0];

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
                    <template #content>
                        <p class="chart-title">Anomaly History</p>

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

                <DashboardCard class="last-alert">
                    <template #content> Last Alert </template>
                </DashboardCard>

                <DashboardCard class="alert-count">
                    <template #content>Alert Count</template>
                </DashboardCard>
            </section>
        </div>
    </section>
</template>

<style lang="scss" scoped src="~/assets/scss/pages/UserDashboard.scss"></style>
