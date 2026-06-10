<script lang="ts" setup>
import type { MonitoredDevice } from "~/types/types";

const { registerDevice, getDevices, deleteDevice } = useDevices();
const { startConnection, onDeviceStatusChanged, stopConnection } = useSignalR();

const isModalOpened = ref(false);
const devices = ref<MonitoredDevice[]>([]);

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

const loadDevices = async () => {
    try {
        devices.value = await getDevices();
    } catch (e) {
        console.error("Failed to fetch devices: ", e);
    }
};

const handleSubmit = async () => {
    try {
        const newDevice = await registerDevice({
            id: form.id,
            name: form.name,
            ipAddress: form.ipAddress,
            sshUsername: form.sshUsername,
            sshPassword: form.sshPassword,
            status: form.status,
            lastHeartbeat: form.lastHeartbeat,
        });

        devices.value.push(newDevice);

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
    await deleteDevice(id);
    await loadDevices();
};

onMounted(async () => {
    await loadDevices();
    startConnection();

    onDeviceStatusChanged((data) => {
        const device = devices.value.find((d) => d.id === data.id);
        if (device) {
            device.status = data.status;
        }
    });
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
                    <div class="left-info">
                        <p class="name">{{ device.name }}</p>
                        <p class="ip">{{ device.ipAddress }}</p>
                    </div>

                    <div class="right-status">
                        <p :class="['status', device.status?.toLowerCase()]">
                            {{ device.status }}
                        </p>
                        <Icon
                            @click="handleDelete(device.id)"
                            class="delete-icon"
                            name="material-symbols:delete"
                        />
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
