import type { LoginDTO, User, UserDTO } from "~/types/types";

export const useAuth = () => {
    const config = useRuntimeConfig();
    const baseUrl = config.public.apiBase;

    const isAuthenticated = useState<boolean>(
        "auth_authenticated",
        () => false,
    );

    const user = useState<UserDTO | null>("auth_user", () => null);

    const checkSession = async () => {
        const reqHeaders = useRequestHeaders(["cookie"]);

        try {
            const res = await $fetch<{ valid: boolean; user?: UserDTO }>(
                `${baseUrl}/api/users/verifyToken`,
                {
                    headers: reqHeaders,
                    credentials: "include",
                },
            );

            isAuthenticated.value = res.valid;
            user.value = res.user || null;
        } catch (e) {
            console.error("Check Session Failed: ", e);
            isAuthenticated.value = false;
            user.value = null;
        }
    };

    const login = async (credentials: LoginDTO) => {
        await $fetch(`${baseUrl}/api/users/login`, {
            method: "POST",
            body: credentials,
            credentials: "include",
        });

        await checkSession();
    };

    const register = async (user: User) => {
        await $fetch(`${baseUrl}/api/users/create`, {
            method: "POST",
            body: user,
            credentials: "include",
        });

        await checkSession();
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
            user.value = null;
            await navigateTo("/login");
        }
    };

    return {
        user,
        isAuthenticated,
        checkSession,
        register,
        login,
        logout,
    };
};
