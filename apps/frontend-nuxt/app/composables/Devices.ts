import type { MonitoredDevice } from "~/types/types";

export const useDevices = () => {
    const config = useRuntimeConfig();
    const baseUrl = config.public.apiBase;

    const registerDevice = async (monitoredDevice: MonitoredDevice) => {
        return await $fetch(`${baseUrl}/api/devices/register`, {
            method: "POST",
            credentials: "include",
            body: monitoredDevice,
        });
    };

    return { registerDevice };
};
