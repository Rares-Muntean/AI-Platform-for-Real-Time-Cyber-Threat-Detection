import type { LoginDTO, User } from "~/types/types";

export const useAuth = () => {
    const config = useRuntimeConfig();
    const baseUrl = config.public.apiBase;

    const isAuthenticated = useState<boolean>(
        "auth_authenticated",
        () => false,
    );

    const checkSession = async () => {
        const reqHeaders = useRequestHeaders(["cookie"]);

        try {
            const res = await $fetch<{ valid: boolean }>(
                `${baseUrl}/api/users/verifyToken`,
                {
                    headers: reqHeaders,
                    credentials: "include",
                },
            );
            isAuthenticated.value = res.valid;
        } catch (e) {
            console.error("Check Session Failed: ", e);
            isAuthenticated.value = false;
        }
    };

    const login = async (credentials: LoginDTO) => {
        await $fetch(`${baseUrl}/api/users/login`, {
            method: "POST",
            body: credentials,
            credentials: "include",
        });

        isAuthenticated.value = true;
    };

    const register = async (user: User) => {
        await $fetch(`${baseUrl}/api/users/create`, {
            method: "POST",
            body: user,
            credentials: "include",
        });

        isAuthenticated.value = true;
    };

    const logout = async () => {
        try {
            await $fetch(`${baseUrl}/api/users/logout`, {
                method: "POST",
                credentials: "include",
            });
        } catch (e) {
            console.error("Logout request failed: ", e);
        } finally {
            isAuthenticated.value = false;
            await navigateTo("/login");
        }
    };

    return {
        isAuthenticated,
        checkSession,
        register,
        login,
        logout,
    };
};
