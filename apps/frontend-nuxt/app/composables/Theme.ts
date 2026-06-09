export const useTheme = () => {
    const theme = useState<"dark" | "light">("theme_mode", () => "dark");

    const toggleTheme = () => {
        theme.value = theme.value === "dark" ? "light" : "dark";
        applyTheme();
    };

    const applyTheme = () => {
        if (import.meta.client) {
            document.documentElement.setAttribute("data-theme", theme.value);
            localStorage.setItem("theme_preference", theme.value);
        }
    };

    onMounted(() => {
        const savedTheme = localStorage.getItem("theme_preference") as
            | "dark"
            | "light"
            | null;

        if (savedTheme) {
            theme.value = savedTheme;
        }
        applyTheme();
    });

    return {
        theme,
        toggleTheme,
    };
};
