(function () {
    const savedTheme = localStorage.getItem("theme_preference") || "dark";
    document.documentElement.setAttribute("data-theme", savedTheme);
})();
