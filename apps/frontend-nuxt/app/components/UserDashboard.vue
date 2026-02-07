<script lang="ts" setup>
const yAxisLabels = [70, 60, 50, 40, 30, 20, 10, 0];
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
                            <img
                                src="/images/icons/material-symbols--dashboard-2.svg"
                                alt=""
                            />
                            <p class="item-name">Dashboard</p>
                        </div>

                        <div class="item">
                            <img
                                src="/images/icons/material-symbols--bolt-rounded.svg"
                                alt=""
                            />
                            <p class="item-name">Live Feed</p>
                        </div>

                        <div class="item">
                            <img
                                src="/images/icons//material-symbols--shield-rounded.svg"
                                alt=""
                            />
                            <p class="item-name">Incidents</p>
                        </div>
                    </div>
                </div>

                <div class="nav-group">
                    <p class="nav-title">SYSTEM</p>
                    <div class="items">
                        <div class="item">
                            <img
                                src="/images/icons/material-symbols--settings-rounded.svg"
                                alt=""
                            />
                            <p class="item-name">Settings</p>
                        </div>

                        <div class="item">
                            <img
                                src="/images/icons/material-symbols--partly-cloudy-night-rounded (1).svg"
                                alt=""
                            />
                            <p class="item-name">Night Mode</p>
                        </div>
                    </div>
                </div>

                <div class="nav-group">
                    <p class="nav-title">ACCOUNT</p>
                    <div class="items">
                        <div class="item">
                            <img
                                src="/images/icons/material-symbols--account-circle.svg"
                                alt=""
                            />
                            <p class="item-name">Ion Popescu</p>
                        </div>

                        <div class="item">
                            <img
                                src="/images/icons/material-symbols--exit-to-app-rounded.svg"
                                alt=""
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
                <div class="anomaly-history">
                    <p class="chart-title">Anomaly History</p>

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
                </div>

                <div></div>
            </section>
        </div>
    </section>
</template>

<style lang="scss" src="~/assets/scss/scoped/UserDashboard.scss"></style>
