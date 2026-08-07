const DEFAULT_SETTINGS = {
    defaultFetchPeriod: "recent",
    emailsPerPage: 25,
    autoRefresh: true,
    notifications: true,
    riskThreshold: 70
};

export function getSettings() {
    const saved = localStorage.getItem("tunamail-settings");
    return saved ? JSON.parse(saved) : DEFAULT_SETTINGS;
}

export function saveSettings(settings) {
    localStorage.setItem(
        "tunamail-settings",
        JSON.stringify(settings)
    );
}
