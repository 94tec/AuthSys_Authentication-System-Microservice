/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: ["class"],
  content: [
    "./src/**/*.{ts,tsx}",
  ],
  theme: {
    container: {
      center: true,
      padding: "1.5rem",
      screens: { "2xl": "1400px" },
    },
    extend: {
      colors: {
        border: "hsl(var(--border))",
        input: "hsl(var(--input))",
        ring: "hsl(var(--ring))",
        background: "hsl(var(--background))",
        foreground: "hsl(var(--foreground))",
        primary: {
          DEFAULT: "hsl(var(--primary))",
          foreground: "hsl(var(--primary-foreground))",
        },
        secondary: {
          DEFAULT: "hsl(var(--secondary))",
          foreground: "hsl(var(--secondary-foreground))",
        },
        destructive: {
          DEFAULT: "hsl(var(--destructive))",
          foreground: "hsl(var(--destructive-foreground))",
        },
        muted: {
          DEFAULT: "hsl(var(--muted))",
          foreground: "hsl(var(--muted-foreground))",
        },
        accent: {
          DEFAULT: "hsl(var(--accent))",
          foreground: "hsl(var(--accent-foreground))",
        },
        popover: {
          DEFAULT: "hsl(var(--popover))",
          foreground: "hsl(var(--popover-foreground))",
        },
        card: {
          DEFAULT: "hsl(var(--card))",
          foreground: "hsl(var(--card-foreground))",
        },
        success: {
          DEFAULT: "hsl(var(--success))",
          foreground: "hsl(var(--success-foreground))",
        },
        warning: {
          DEFAULT: "hsl(var(--warning))",
          foreground: "hsl(var(--warning-foreground))",
        },
        expedition: {
          forest: "#0B1F1A",
          sand: "#F5F1E8",
          clay: "#C9742F",
          moss: "#3D5A4C",
          surface: "#E8E2D4",
          rust: "#8B2E2E",
        },
      },
      fontFamily: {
        display: ["var(--font-fraunces)", "Georgia", "serif"],
        sans: ["var(--font-inter)", "system-ui", "sans-serif"],
        mono: ["var(--font-jetbrains)", "monospace"],
      },
      borderRadius: {
        lg: "var(--radius)",
        md: "calc(var(--radius) - 2px)",
        sm: "calc(var(--radius) - 4px)",
      },
      keyframes: {
        // Replaces tailwindcss-animate — defined inline so no plugin needed
        "accordion-down": {
          from: { height: "0" },
          to: { height: "var(--radix-accordion-content-height)" },
        },
        "accordion-up": {
          from: { height: "var(--radix-accordion-content-height)" },
          to: { height: "0" },
        },
        "stamp-in": {
          "0%": { transform: "scale(2.2) rotate(-12deg)", opacity: "0" },
          "60%": { transform: "scale(0.95) rotate(2deg)", opacity: "1" },
          "100%": { transform: "scale(1) rotate(-3deg)", opacity: "1" },
        },
        "fade-up": {
          "0%": { transform: "translateY(8px)", opacity: "0" },
          "100%": { transform: "translateY(0)", opacity: "1" },
        },
        "fade-in": {
          "0%": { opacity: "0" },
          "100%": { opacity: "1" },
        },
        "fade-out": {
          "0%": { opacity: "1" },
          "100%": { opacity: "0" },
        },
        "zoom-in-95": {
          "0%": { transform: "scale(0.95)", opacity: "0" },
          "100%": { transform: "scale(1)", opacity: "1" },
        },
        "zoom-out-95": {
          "0%": { transform: "scale(1)", opacity: "1" },
          "100%": { transform: "scale(0.95)", opacity: "0" },
        },
        "slide-in-from-top": {
          "0%": { transform: "translateY(-4px)", opacity: "0" },
          "100%": { transform: "translateY(0)", opacity: "1" },
        },
        "slide-in-from-bottom": {
          "0%": { transform: "translateY(4px)", opacity: "0" },
          "100%": { transform: "translateY(0)", opacity: "1" },
        },
        "spin": {
          "0%": { transform: "rotate(0deg)" },
          "100%": { transform: "rotate(360deg)" },
        },
        "pulse": {
          "0%, 100%": { opacity: "1" },
          "50%": { opacity: "0.5" },
        },
      },
      animation: {
        // Accordion (Radix)
        "accordion-down": "accordion-down 0.2s ease-out",
        "accordion-up": "accordion-up 0.2s ease-out",
        // Passport stamp
        "stamp-in": "stamp-in 0.45s cubic-bezier(0.34, 1.56, 0.64, 1) forwards",
        // Radix dropdown/dialog open/close animations
        "fade-in": "fade-in 0.15s ease-out",
        "fade-out": "fade-out 0.1s ease-in",
        "zoom-in-95": "zoom-in-95 0.15s ease-out",
        "zoom-out-95": "zoom-out-95 0.1s ease-in",
        "slide-in-from-top": "slide-in-from-top 0.15s ease-out",
        "slide-in-from-bottom": "slide-in-from-bottom 0.15s ease-out",
        "fade-up": "fade-up 0.4s ease-out forwards",
        "spin": "spin 1s linear infinite",
        "pulse": "pulse 2s ease-in-out infinite",
      },
    },
  },
  // NO external plugins — all animations defined inline above.
  // tailwindcss-animate removed to avoid missing-module crash at build time.
  // Install with: npm install tailwindcss-animate
  // then re-add: plugins: [require("tailwindcss-animate")]
  plugins: [],
};
