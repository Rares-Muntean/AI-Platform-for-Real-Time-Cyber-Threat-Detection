import type {
    AgentConfigPayload,
    AgentStatusResponse,
    CalibratePayload,
    MonitoredDevice,
} from "~/types/types";

export const useDevices = () => {
    const config = useRuntimeConfig();
    const baseUrl = config.public.apiBase;

    const getDevices = async () => {
        return await useFetch<MonitoredDevice[]>(`${baseUrl}/api/devices/all`, {
            method: "GET",
            headers: useRequestHeaders(["cookie"]),
            credentials: "include",
        });
    };

    const registerDevice = async (monitoredDevice: MonitoredDevice) => {
        return await $fetch<MonitoredDevice>(
            `${baseUrl}/api/devices/register`,
            {
                method: "POST",
                credentials: "include",
                body: monitoredDevice,
            },
        );
    };

    const getDeviceStatus = async (id: number) => {
        return await $fetch<AgentStatusResponse>(
            `${baseUrl}/api/devices/status/${id}`,
            {
                method: "GET",
                credentials: "include",
            },
        );
    };

    const calibrateDevice = async (id: number, payload: CalibratePayload) => {
        return await $fetch<{
            started: boolean;
            message: string;
            calibration: any;
        }>(`${baseUrl}/api/devices/calibrate/${id}`, {
            method: "POST",
            credentials: "include",
            body: payload,
        });
    };

    const updateDeviceConfig = async (
        id: number,
        payload: AgentConfigPayload,
    ) => {
        return await $fetch<{ saved: boolean; message: string }>(
            `${baseUrl}/api/devices/config/${id}`,
            {
                method: "POST",
                credentials: "include",
                body: payload,
            },
        );
    };

    const deleteDevice = async (id: number) => {
        await $fetch(`${baseUrl}/api/devices/delete/${id}`, {
            method: "DELETE",
            credentials: "include",
        });
    };

    return {
        getDevices,
        registerDevice,
        getDeviceStatus,
        calibrateDevice,
        updateDeviceConfig,
        deleteDevice,
    };
};
