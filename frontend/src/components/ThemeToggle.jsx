import useTheme from "../hooks/useTheme";

export default function ThemeToggle() {
    const { theme, toggleTheme } = useTheme();

    return (
        <button
            onClick={toggleTheme}
            className="btn-primary"
            style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
                padding: '0.5rem 1rem',
                borderRadius: '8px'
            }}
        >
            {theme === "dark" ? "☀️ Light Mode" : "🌙 Dark Mode"}
        </button>
    );
}
