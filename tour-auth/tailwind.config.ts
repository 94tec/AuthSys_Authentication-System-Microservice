import type { Config } from "tailwindcss"

const config: Config = {
  darkMode: ["class"],
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        // Expedition palette
        forest:    { DEFAULT: "#0B1F1A", 50: "#1a3830", 100: "#0B1F1A" },
        sand:      { DEFAULT: "#F5F1E8", 50: "#faf8f3", 100: "#F5F1E8", 200: "#E8E2D4" },
        clay:      { DEFAULT: "#C9742F", 50: "#f5e6d8", 100: "#e8c49a", 500: "#C9742F", 700: "#a05a1e" },
        moss:      { DEFAULT: "#3D5A4C", 50: "#d1ddd8", 500: "#3D5A4C", 700: "#2a3f35" },
        rust:      { DEFAULT: "#8B2E2E", 50: "#f5d5d5", 500: "#8B2E2E", 700: "#6b2020" },
        // Semantic aliases
        background: "hsl(var(--background))",
        foreground:  "hsl(var(--foreground))",
        primary: {
          DEFAULT:    "hsl(var(--primary))",
          foreground: "hsl(var(--primary-foreground))",
        },
        secondary: {
          DEFAULT:    "hsl(var(--secondary))",
          foreground: "hsl(var(--secondary-foreground))",
        },
        muted: {
          DEFAULT:    "hsl(var(--muted))",
          foreground: "hsl(var(--muted-foreground))",
        },
        accent: {
          DEFAULT:    "hsl(var(--accent))",
          foreground: "hsl(var(--accent-foreground))",
        },
        destructive: {
          DEFAULT:    "hsl(var(--destructive))",
          foreground: "hsl(var(--destructive-foreground))",
        },
        card: {
          DEFAULT:    "hsl(var(--card))",
          foreground: "hsl(var(--card-foreground))",
        },
        border:  "hsl(var(--border))",
        input:   "hsl(var(--input))",
        ring:    "hsl(var(--ring))",
      },
      fontFamily: {
        display: ["var(--font-fraunces)", "Georgia", "serif"],
        sans:    ["var(--font-inter)", "system-ui", "sans-serif"],
        mono:    ["var(--font-jetbrains)", "monospace"],
      },
      borderRadius: {
        lg: "var(--radius)",
        md: "calc(var(--radius) - 2px)",
        sm: "calc(var(--radius) - 4px)",
      },
      keyframes: {
        "stamp-in": {
          "0%":   { transform: "scale(1.4) rotate(-8deg)", opacity: "0" },
          "60%":  { transform: "scale(0.95) rotate(2deg)", opacity: "1" },
          "100%": { transform: "scale(1) rotate(0deg)", opacity: "1" },
        },
        "fade-up": {
          "0%":   { opacity: "0", transform: "translateY(12px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        "dot-trail": {
          "0%, 100%": { opacity: "0.3" },
          "50%":      { opacity: "1" },
        },
      },
      animation: {
        "stamp-in": "stamp-in 0.5s cubic-bezier(0.34, 1.56, 0.64, 1) forwards",
        "fade-up":  "fade-up 0.4s ease forwards",
        "dot-trail": "dot-trail 1.5s ease-in-out infinite",
      },
    },
  },
  plugins: [],
}
export default config
