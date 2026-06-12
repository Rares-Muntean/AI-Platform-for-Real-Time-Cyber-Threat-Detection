import { defineStore } from "pinia";
import type { ThreatAlert } from "~/types/types";

export const useAlertsStore = defineStore("alerts", () => {
    const config = useRuntimeConfig();
    const baseUrl = config.public.apiBase;

    const recentAlerts = ref<ThreatAlert[]>([]);
    const historyAlerts = ref<ThreatAlert[]>([]);
    const lastAlert = ref<ThreatAlert | null>(null);

    const fetchRecent = async () => {
        recentAlerts.value = await $fetch<ThreatAlert[]>(
            `${baseUrl}/api/alerts/recent`,
            {
                credentials: "include",
            },
        );
    };

    const fetchHistory = async () => {
        historyAlerts.value = await $fetch<ThreatAlert[]>(
            `${baseUrl}/api/alerts/all`,
            {
                credentials: "include",
            },
        );
    };

    const handleIncomingAlert = (newAlert: ThreatAlert) => {
        lastAlert.value = newAlert;
        recentAlerts.value.unshift(newAlert);
        historyAlerts.value.unshift(newAlert);
    };

    return {
        recentAlerts,
        historyAlerts,
        lastAlert,
        fetchRecent,
        fetchHistory,
        handleIncomingAlert,
    };
});
