import type { User } from "~/types/types";

export const useUsers = () => {
    const config = useRuntimeConfig();
    const baseUrl = config.public.apiBase;

    const createAccount = async (user: User) => {
        return await $fetch(`${baseUrl}/api/users/create`, {
            method: "POST",
            body: user,
        });
    };

    return { createAccount };
};
