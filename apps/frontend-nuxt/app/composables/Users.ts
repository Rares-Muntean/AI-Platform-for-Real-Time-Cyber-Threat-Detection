import type { LoginDTO, TokenResponse, User } from "~/types/types";

export const useUsers = () => {
    const config = useRuntimeConfig();
    const baseUrl = config.public.apiBase;

    const createAccount = async (user: User): Promise<TokenResponse> => {
        return await $fetch(`${baseUrl}/api/users/create`, {
            method: "POST",
            body: user,
        });
    };

    const loginUser = async (user: LoginDTO): Promise<TokenResponse> => {
        return await $fetch(`${baseUrl}/api/users/login`, {
            method: "POST",
            body: user,
        });
    };

    return { createAccount, loginUser };
};
