import type { Metadata, Viewport } from "next";
import { Inter, Playfair_Display, JetBrains_Mono } from "next/font/google";
import { Toaster } from "sonner";
import { VisitorProvider } from "@/components/landing/visitor-provider";
import "./globals.css";

const inter = Inter({
    subsets: ["latin"],
    variable: "--font-inter",
    display: "swap",
});

const playfair = Playfair_Display({
    subsets: ["latin"],
    variable: "--font-playfair",
    display: "swap",
});

const jetbrainsMono = JetBrains_Mono({
    subsets: ["latin"],
    variable: "--font-jetbrains-mono",
    display: "swap",
});

const SITE_URL = process.env.NEXT_PUBLIC_SITE_URL ?? "https://damuchisafaris.co.ke";

export const metadata: Metadata = {
    metadataBase: new URL(SITE_URL),
    title: {
        default: "Damuchi Safaris | East Africa Tours & Safaris",
        template: "%s | Damuchi Safaris",
    },
    description:
        "Safaris across Kenya, Tanzania, Uganda & Rwanda — beach escapes, mountain treks, gorilla encounters, and cultural tours. Book directly with local guides, transparent pricing, no quotes needed.",
    keywords: [
        "Kenya safari",
        "Tanzania safari",
        "Uganda gorilla trekking",
        "Rwanda gorilla trekking",
        "East Africa tours",
        "Maasai Mara",
        "Serengeti",
        "Diani Beach",
        "Zanzibar",
    ],
    authors: [{ name: "Damuchi Safaris" }],
    robots: {
        index: true,
        follow: true,
        googleBot: { index: true, follow: true },
    },
    icons: {
        icon: "/favicon.ico",
        shortcut: "/favicon-16x16.png",
        apple: "/apple-touch-icon.png",
    },
    manifest: "/site.webmanifest",
    openGraph: {
        type: "website",
        locale: "en_US",
        url: SITE_URL,
        siteName: "Damuchi Safaris",
        title: "Damuchi Safaris | East Africa Tours & Safaris",
        description:
            "Savannahs, coastlines, volcanoes, and gorillas — book tours run by local experts across East Africa.",
        images: [
            {
                url: "/og-image.jpg",
                width: 1200,
                height: 630,
                alt: "Damuchi Safaris — East Africa tours",
            },
        ],
    },
    twitter: {
        card: "summary_large_image",
        title: "Damuchi Safaris | East Africa Tours & Safaris",
        description: "Book safaris across Kenya, Tanzania, Uganda & Rwanda with local guides.",
        images: ["/og-image.jpg"],
    },
};

export const viewport: Viewport = {
    themeColor: [
        { media: "(prefers-color-scheme: light)", color: "#C8860A" },
        { media: "(prefers-color-scheme: dark)", color: "#2C1810" },
    ],
    width: "device-width",
    initialScale: 1,
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
    return (
        <html
            lang="en"
            suppressHydrationWarning
            className={`${inter.variable} ${playfair.variable} ${jetbrainsMono.variable}`}
        >
        <body className="min-h-screen bg-background font-sans antialiased">
        <VisitorProvider>
            {children}
        </VisitorProvider>
        <Toaster/>
        </body>
        </html>
    );
}