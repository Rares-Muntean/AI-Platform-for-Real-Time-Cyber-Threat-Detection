export default defineNuxtRouteMiddleware(async (to, from) => {
    const { isAuthenticated, checkSession } = useAuth();

    await checkSession();

    if (!isAuthenticated.value) {
        return navigateTo("/login");
    }
});
