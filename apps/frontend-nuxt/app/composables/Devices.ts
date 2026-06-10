import type { MonitoredDevice } from "~/types/types";

export const useDevices = () => {
    const config = useRuntimeConfig();
    const baseUrl = config.public.apiBase;

    const getDevices = async () => {
        return await $fetch<MonitoredDevice[]>(`${baseUrl}/api/devices/all`, {
            method: "GET",
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

    const deleteDevice = async (id: number) => {
        await $fetch(`${baseUrl}/api/devices/delete/${id}`, {
            method: "DELETE",
            credentials: "include",
        });
    };

    return { getDevices, registerDevice, deleteDevice };
};
