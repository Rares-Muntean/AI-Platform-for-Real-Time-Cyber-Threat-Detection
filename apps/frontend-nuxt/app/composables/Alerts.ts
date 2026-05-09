import type { ThreatAlert } from "~/models/threatAlert";

export const useAlerts = () => {
    const config = useRuntimeConfig();
    const baseUrl = config.public.apiBase;

    const getHistory = async () => {
        return await useFetch<ThreatAlert>(`${baseUrl}/api/alerts/all`, {
            key: "alerts-history",
        });
    };

    return {
        getHistory,
    };
};
