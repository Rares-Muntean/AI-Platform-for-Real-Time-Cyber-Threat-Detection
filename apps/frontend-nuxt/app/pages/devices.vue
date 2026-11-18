<script lang="ts" setup>
import type { AgentStatusData, MonitoredDevice } from "~/types/types";

const {
    registerDevice,
    getDevices,
    getDeviceStatus,
    calibrateDevice,
    updateDeviceConfig,
    deleteDevice,
} = useDevices();
const { startConnection, onDeviceStatusChanged, stopConnection } = useSignalR();
const { data: devices, refresh } = await getDevices();

const isModalOpened = ref(false);
if (!devices.value) devices.value = [];

const toggleModal = () => {
    isModalOpened.value = !isModalOpened.value;
};

const form: MonitoredDevice = reactive({
    id: 0,
    name: "",
    ipAddress: "",
    sshUsername: "",
    sshPassword: "",
    status: "",
    lastHeartbeat: new Date(),
});

const agentData = reactive<Record<number, AgentStatusData>>({});

const configForms = reactive<
    Record<
        number,
        {
            interface: string;
            captureMode: string;
            firewallEnabled: boolean;
            blockDurationSeconds: number;
        }
    >
>({});

const calibrateForms = reactive<
    Record<number, { duration: number; mode: "update" | "replace" }>
>({});

const busyId = ref<number | null>(null);
const pollTimers: Record<number, ReturnType<typeof setInterval>> = {};

const stopPolling = (id: number) => {
    if (pollTimers[id]) {
        clearInterval(pollTimers[id]);
        delete pollTimers[id];
    }
};

const fetchAgentStatus = async (device: MonitoredDevice, syncForm = false) => {
    try {
        const res = await getDeviceStatus(device.id);

        if (!res.online || !res.data) {
            delete agentData[device.id];
            stopPolling(device.id);
            return;
        }

        agentData[device.id] = res.data;

        if (!calibrateForms[device.id]) {
            calibrateForms[device.id] = { duration: 20, mode: "update" };
        }
        if (!configForms[device.id] || syncForm) {
            configForms[device.id] = {
                interface: res.data.interface || "",
                captureMode: res.data.captureMode || "nfqueue",
                firewallEnabled: res.data.firewallEnabled ?? true,
                blockDurationSeconds: res.data.blockDurationSeconds || 60,
            };
        }

        const calStatus = res.data.calibration.status;
        if (calStatus === "recording" || calStatus === "training") {
            if (!pollTimers[device.id]) {
                pollTimers[device.id] = setInterval(
                    () => fetchAgentStatus(device),
                    2000,
                );
            }
        } else {
            stopPolling(device.id);
        }
    } catch (e) {
        console.error(`Status error for device ${device.id}:`, e);
        stopPolling(device.id);
    }
};

const handleApplyConfig = async (device: MonitoredDevice) => {
    const cfg = configForms[device.id];
    if (!cfg) return;

    busyId.value = device.id;
    try {
        const isVpn = cfg.interface === "wg0" || cfg.interface === "tun0";
        await updateDeviceConfig(device.id, {
            interface: cfg.interface || null,
            captureMode: cfg.captureMode,
            firewallEnabled: cfg.firewallEnabled,
            blockDurationSeconds: cfg.blockDurationSeconds,
            deviceIpOverride: isVpn ? device.ipAddress : null,
        });

        setTimeout(async () => {
            await fetchAgentStatus(device, true);
            busyId.value = null;
        }, 3000);
    } catch (e) {
        console.error("Failed to update config:", e);
        busyId.value = null;
    }
};

const handleCalibrate = async (device: MonitoredDevice) => {
    const cal = calibrateForms[device.id] || { duration: 20, mode: "update" };
    try {
        await calibrateDevice(device.id, cal);
        await fetchAgentStatus(device);
    } catch (e) {
        console.error("Failed to start calibration:", e);
    }
};

const handleSubmit = async () => {
    try {
        await registerDevice({ ...form });
        await refresh();

        form.name = "";
        form.ipAddress = "";
        form.sshUsername = "";
        form.sshPassword = "";
        toggleModal();
    } catch (e) {
        console.error("Failed to register device: ", e);
    }
};

const handleDelete = async (id: number) => {
    stopPolling(id);
    await deleteDevice(id);
    await refresh();
};

onMounted(async () => {
    startConnection();

    for (const d of devices.value || []) {
        fetchAgentStatus(d, true);
    }

    onDeviceStatusChanged((data) => {
        const device = devices.value?.find((d) => d.id === data.id);
        if (device) {
            device.status = data.status;
            devices.value = [...(devices.value || [])];
            fetchAgentStatus(device, true);
        }
    });
});

onBeforeUnmount(() => {
    Object.keys(pollTimers).forEach((id) => stopPolling(Number(id)));
    stopConnection();
});
</script>

<template>
    <div class="section">
        <p class="panel-title">Devices</p>
        <div class="content">
            <div class="devices-header">
                <p class="devices-title">Monitored Nodes</p>

                <button @click="toggleModal" class="btn ui-size">
                    <Icon name="material-symbols:add-circle" size="18" />
                    <p>Add Device</p>
                </button>
            </div>

            <Separator class="primary" />

            <div class="device-list">
                <div
                    v-for="device in devices"
                    :key="device.id"
                    class="device-card"
                >
                    <div class="card-header">
                        <div class="left-info">
                            <p class="name">{{ device.name }}</p>
                            <p class="ip">{{ device.ipAddress }}</p>
                        </div>

                        <div class="right-status">
                            <span
                                v-if="agentData[device.id]"
                                class="threshold-pill"
                            >
                                Threshold:
                                {{ agentData[device.id]!.threshold.toFixed(4) }}
                            </span>

                            <p
                                :class="[
                                    'status',
                                    device.status?.toLowerCase(),
                                ]"
                            >
                                {{ device.status }}
                            </p>

                            <Icon
                                @click="fetchAgentStatus(device, true)"
                                class="action-icon"
                                name="material-symbols:refresh"
                                size="18"
                            />
                            <Icon
                                @click="handleDelete(device.id)"
                                class="delete-icon"
                                name="material-symbols:delete"
                                size="18"
                            />
                        </div>
                    </div>

                    <div
                        v-if="agentData[device.id] && configForms[device.id]"
                        class="separator-div"
                    ></div>

                    <div
                        v-if="agentData[device.id] && configForms[device.id]"
                        class="agent-panel"
                    >
                        <div class="panel-column">
                            <p class="panel-heading">
                                Firewall & Capture Engine
                            </p>

                            <div class="controls-row">
                                <div class="control-group">
                                    <label>Mode</label>
                                    <select
                                        v-model="
                                            configForms[device.id]!.captureMode
                                        "
                                    >
                                        <option value="nfqueue">
                                            NFQUEUE (Kernel)
                                        </option>
                                        <option value="scapy">
                                            SCAPY (Raw)
                                        </option>
                                    </select>
                                </div>

                                <div class="control-group">
                                    <label>Interface</label>
                                    <select
                                        v-model="
                                            configForms[device.id]!.interface
                                        "
                                    >
                                        <option value="">All / Default</option>
                                        <option value="enp0s3">
                                            enp0s3 (LAN)
                                        </option>
                                        <option value="wg0">
                                            wg0 (WireGuard VPN)
                                        </option>
                                        <option value="tun0">
                                            tun0 (OpenVPN)
                                        </option>
                                    </select>
                                </div>

                                <div class="control-group">
                                    <label>Block Duration</label>
                                    <select
                                        v-model.number="
                                            configForms[device.id]!
                                                .blockDurationSeconds
                                        "
                                    >
                                        <option :value="30">30s</option>
                                        <option :value="60">60s</option>
                                        <option :value="300">5m</option>
                                        <option :value="3600">1h</option>
                                        <option :value="86400">24h</option>
                                    </select>
                                </div>
                            </div>

                            <div class="panel-footer">
                                <label class="firewall-toggle">
                                    <input
                                        type="checkbox"
                                        v-model="
                                            configForms[device.id]!
                                                .firewallEnabled
                                        "
                                    />
                                    <span
                                        >Auto-Block ({{
                                            agentData[device.id]!
                                                .blockDurationSeconds
                                        }}s)</span
                                    >
                                </label>

                                <button
                                    class="btn secondary ui-size"
                                    :disabled="busyId === device.id"
                                    @click="handleApplyConfig(device)"
                                >
                                    <p>
                                        {{
                                            busyId === device.id
                                                ? "Applying..."
                                                : "Apply"
                                        }}
                                    </p>
                                </button>
                            </div>
                        </div>

                        <div class="panel-column right-col">
                            <p class="panel-heading">AI Baseline Calibration</p>

                            <div class="controls-row">
                                <div class="control-group">
                                    <label>Training Mode</label>
                                    <select
                                        v-model="
                                            calibrateForms[device.id]!.mode
                                        "
                                    >
                                        <option value="update">
                                            Update (Keep Old)
                                        </option>
                                        <option value="replace">
                                            Replace (Fresh)
                                        </option>
                                    </select>
                                </div>

                                <div class="control-group">
                                    <label>Duration</label>
                                    <select
                                        v-model.number="
                                            calibrateForms[device.id]!.duration
                                        "
                                    >
                                        <option :value="20">20s</option>
                                        <option :value="60">1m</option>
                                        <option :value="120">2m</option>
                                        <option :value="300">5m</option>
                                        <option :value="600">10m</option>
                                        <option :value="3600">1h</option>
                                    </select>
                                </div>
                            </div>

                            <div class="panel-footer">
                                <button
                                    class="btn ui-size calibrate-btn"
                                    :disabled="
                                        agentData[device.id]!.calibration
                                            .status !== 'idle'
                                    "
                                    @click="handleCalibrate(device)"
                                >
                                    <Icon
                                        name="material-symbols:build"
                                        size="16"
                                    />

                                    <p
                                        v-if="
                                            agentData[device.id]!.calibration
                                                .status === 'recording'
                                        "
                                    >
                                        Recording ({{
                                            agentData[device.id]!.calibration
                                                .secondsRemaining
                                        }}s •
                                        {{
                                            agentData[device.id]!.calibration
                                                .recordedFlows
                                        }}
                                        flows)
                                    </p>

                                    <p
                                        v-else-if="
                                            agentData[device.id]!.calibration
                                                .status === 'training'
                                        "
                                    >
                                        Training Model...
                                    </p>

                                    <p v-else>Calibrate Model</p>
                                </button>
                            </div>
                        </div>

                        <div
                            v-if="agentData[device.id]!.activeBlocks.length > 0"
                            class="blocked-banner"
                        >
                            <Icon
                                name="material-symbols:shield-lock"
                                size="16"
                            />
                            <span
                                >Blocked:
                                {{
                                    agentData[device.id]!.activeBlocks.join(
                                        ", ",
                                    )
                                }}</span
                            >
                        </div>

                        <p
                            v-if="agentData[device.id]!.calibration.lastMessage"
                            :class="[
                                'cal-msg',
                                agentData[device.id]!.calibration.lastResult,
                            ]"
                        >
                            {{ agentData[device.id]!.calibration.lastMessage }}
                        </p>
                    </div>
                </div>
            </div>
        </div>

        <AddDeviceModal
            title="Add Device"
            subtitle="Enter the network details to register and monitor a new system node."
            v-model="isModalOpened"
        >
            <template #icon>
                <Icon name="material-symbols:library-add-rounded" />
            </template>

            <form class="form" @submit.prevent="handleSubmit">
                <div class="input-wrapper">
                    <input
                        v-model="form.name"
                        type="text"
                        placeholder="Device Name"
                        required
                    />
                    <input
                        v-model="form.ipAddress"
                        type="text"
                        placeholder="IP Address"
                        required
                    />
                    <input
                        v-model="form.sshUsername"
                        type="text"
                        placeholder="SSH Username"
                        required
                    />
                    <input
                        v-model="form.sshPassword"
                        type="password"
                        placeholder="SSH Password"
                        required
                    />
                </div>

                <div class="action-btns">
                    <button
                        type="button"
                        @click="toggleModal"
                        class="btn secondary ui-size"
                    >
                        Cancel
                    </button>
                    <button type="submit" class="btn ui-size">
                        Deploy Agent
                    </button>
                </div>
            </form>
        </AddDeviceModal>
    </div>
</template>

<style lang="scss" scoped src="~/assets/scss/pages/devices.scss"></style>
