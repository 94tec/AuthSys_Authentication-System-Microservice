/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: ["class"],
  content: [
    "./src/**/*.{ts,tsx,js,jsx,mdx}",
  ],
  theme: {
    container: {
      center: true,
      padding: "1.5rem",
      screens: { "2xl": "1400px" },
    },
    extend: {
      // ── Colors ──────────────────────────────────────────────────────────────
      colors: {
        // HSL-based theme system (from first config)
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

        // Legacy/Static color palette (from second config)
        savanna: "#C8860A",   // warm amber/gold — primary accent
        earth: "#2C1810",    // deep mahogany — dark surfaces, primary text
        dust: "#F5EFE6",     // bone-white — light background
        canopy: "#1A3A2A",   // deep forest green — staff/ops contexts
        stone: "#8C7B6B",    // warm mid-grey — muted text, borders
        sky: "#E8F4F8",      // pale morning blue — hover, subtle fills

        // Expedition palette (from first config)
        expedition: {
          forest: "#0B1F1A",
          sand: "#F5F1E8",
          clay: "#C9742F",
          moss: "#3D5A4C",
          surface: "#E8E2D4",
          rust: "#8B2E2E",
        },

        // Semantic aliases (from second config)
        background: "#F5EFE6",
        foreground: "#2C1810",
        muted: "#8C7B6B",
        accent: "#C8860A",
        "accent-dark": "#9B6508",
        border: "#DDD3C7",
        card: "#FFFFFF",

        // Status colours (from second config)
        "status-pending": "#D97706",
        "status-confirmed": "#15803D",
        "status-cancelled": "#DC2626",
        "status-completed": "#1D4ED8",
        "status-refunded": "#7C3AED",
      },

      // ── Font Family ──────────────────────────────────────────────────────────
      fontFamily: {
        // From first config (with CSS variables)
        display: ["var(--font-fraunces)", "Playfair Display", "Georgia", "serif"],
        sans: ["var(--font-inter)", "Inter", "system-ui", "sans-serif"],
        mono: ["var(--font-jetbrains)", "JetBrains Mono", "Fira Code", "monospace"],
      },

      // ── Font Size ─────────────────────────────────────────────────────────────
      fontSize: {
        "2xs": ["0.65rem", { lineHeight: "1rem" }],
      },

      // ── Border Radius ────────────────────────────────────────────────────────
      borderRadius: {
        lg: "var(--radius)",
        md: "calc(var(--radius) - 2px)",
        sm: "calc(var(--radius) - 4px)",
        "4xl": "2rem",
      },

      // ── Box Shadow ───────────────────────────────────────────────────────────
      boxShadow: {
        "card": "0 1px 3px 0 rgba(44,24,16,0.08), 0 1px 2px -1px rgba(44,24,16,0.05)",
        "card-hover": "0 4px 12px 0 rgba(44,24,16,0.12)",
        "savanna": "0 0 0 3px rgba(200,134,10,0.25)",
      },

      // ── Keyframes ─────────────────────────────────────────────────────────────
      keyframes: {
        // Accordion animations (Radix UI)
        "accordion-down": {
          from: { height: "0" },
          to: { height: "var(--radix-accordion-content-height)" },
        },
        "accordion-up": {
          from: { height: "var(--radix-accordion-content-height)" },
          to: { height: "0" },
        },

        // Brand animations
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
          "0%": { opacity: "0", transform: "translateY(8px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
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
        "slide-in": {
          from: { transform: "translateX(-100%)" },
          to: { transform: "translateX(0)" },
        },
        shimmer: {
          "0%": { backgroundPosition: "-200% 0" },
          "100%": { backgroundPosition: "200% 0" },
        },
        spin: {
          "0%": { transform: "rotate(0deg)" },
          "100%": { transform: "rotate(360deg)" },
        },
        pulse: {
          "0%, 100%": { opacity: "1" },
          "50%": { opacity: "0.5" },
        },
      },

      // ── Animations ────────────────────────────────────────────────────────────
      animation: {
        // Accordion (Radix UI)
        "accordion-down": "accordion-down 0.2s ease-out",
        "accordion-up": "accordion-up 0.2s ease-out",

        // Brand animations
        "stamp-in": "stamp-in 0.45s cubic-bezier(0.34, 1.56, 0.64, 1) forwards",
        "fade-up": "fade-up 0.4s ease-out forwards",

        // Radix dropdown/dialog animations
        "fade-in": "fade-in 0.15s ease-out",
        "fade-out": "fade-out 0.1s ease-in",
        "zoom-in-95": "zoom-in-95 0.15s ease-out",
        "zoom-out-95": "zoom-out-95 0.1s ease-in",
        "slide-in-from-top": "slide-in-from-top 0.15s ease-out",
        "slide-in-from-bottom": "slide-in-from-bottom 0.15s ease-out",

        // Utility animations
        "slide-in": "slide-in 0.25s ease-out",
        shimmer: "shimmer 1.8s ease-in-out infinite",
        spin: "spin 1s linear infinite",
        pulse: "pulse 2s ease-in-out infinite",
      },
    },
  },
  // ── Plugins ──────────────────────────────────────────────────────────────────
  // No external plugins to avoid missing-module crash at build time.
  // If you want tailwindcss-animate, install with:
  // npm install tailwindcss-animate
  // then uncomment: plugins: [require("tailwindcss-animate")],
  plugins: [],
};