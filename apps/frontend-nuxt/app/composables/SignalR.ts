import * as signalr from "@microsoft/signalr";

export const useSignalR = () => {
    const config = useRuntimeConfig();
    const baseUrl = config.public.apiBase;
    const connection = ref<signalr.HubConnection | null>(null);

    const startConnection = () => {
        if (!import.meta.client) return;

        connection.value = new signalr.HubConnectionBuilder()
            .withUrl(`${baseUrl}/hubs/velox`, {
                withCredentials: true,
            })
            .withAutomaticReconnect()
            .build();

        connection.value
            .start()
            .then(() => console.log("SignalR WebSocket Connection Established"))
            .catch((e) => console.error("SignalR Connection Error: ", e));
    };

    const onRecieveAlert = (callback: (alert: any) => void) => {
        if (!connection.value) return;
        connection.value.on("RecieveAlert", callback);
    };

    const onDeviceStatusChanged = (
        callback: (data: { id: number; status: string }) => void,
    ) => {
        if (!connection.value) return;
        connection.value.on("DeviceStatusChanged", callback);
    };

    const stopConnection = () => {
        if (connection.value) {
            connection.value.stop();
        }
    };

    return {
        startConnection,
        onRecieveAlert,
        onDeviceStatusChanged,
        stopConnection,
    };
};
