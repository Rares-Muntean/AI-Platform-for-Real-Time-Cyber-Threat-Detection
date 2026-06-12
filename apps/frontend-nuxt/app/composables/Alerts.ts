import type { ThreatAlert } from "~/types/types";

export const useAlerts = () => {
    const config = useRuntimeConfig();
    const baseUrl = config.public.apiBase;

    const getHistory = () => {
        return useFetch<ThreatAlert[]>(`${baseUrl}/api/alerts/all`, {
            key: "alerts-history",
            headers: useRequestHeaders(["cookie"]),
            credentials: "include",
        });
    };

    const getRecent = () => {
        return useFetch<ThreatAlert[]>(`${baseUrl}/api/alerts/recent`, {
            key: "alerts-recent",
            headers: useRequestHeaders(["cookie"]),
            credentials: "include",
        });
    };

    const getLast = () => {
        return useFetch<ThreatAlert>(`${baseUrl}/api/alerts/last`, {
            key: "last-alert",
            headers: useRequestHeaders(["cookie"]),
            credentials: "include",
        });
    };

    return {
        getLast,
        getRecent,
        getHistory,
    };
};
