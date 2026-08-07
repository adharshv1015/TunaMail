import { createContext, useEffect, useState } from "react";

export const ThemeContext = createContext();

export function ThemeProvider({ children }) {
    const [theme, setTheme] = useState(() => {
        return localStorage.getItem("theme") || "dark";
    });

    useEffect(() => {
        document.documentElement.classList.remove(
            "light",
            "dark"
        );

        document.documentElement.classList.add(theme);

        localStorage.setItem(
            "theme",
            theme
        );
    }, [theme]);

    const toggleTheme = () => {
        setTheme(prev =>
            prev === "dark"
                ? "light"
                : "dark"
        );
    };

    return (
        <ThemeContext.Provider
            value={{
                theme,
                toggleTheme
            }}
        >
            {children}
        </ThemeContext.Provider>
    );
}
