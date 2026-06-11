import type { ThreatAlert } from "~/types/types";

export const useAlerts = () => {
    const config = useRuntimeConfig();
    const baseUrl = config.public.apiBase;

    const getHistory = async () => {
        return await useFetch<ThreatAlert>(`${baseUrl}/api/alerts/all`, {
            key: "alerts-history",
            headers: useRequestHeaders(["cookie"]),
            credentials: "include",
        });
    };

    const getLast = async () => {
        return await useFetch<ThreatAlert>(`${baseUrl}/api/alerts/last`, {
            key: "last-alert",
            headers: useRequestHeaders(["cookie"]),
            credentials: "include",
        });
    };

    return {
        getLast,
        getHistory,
    };
};
