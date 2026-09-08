import type { NavItem } from "@/types/nav";

export const NAV_LINKS: NavItem[] = [
    {
        href: "/safaris",
        label: "Safaris",
        groups: [
            {
                label: "By Country",
                items: [
                    { href: "/safaris/kenya", label: "Kenya Safaris" },
                    { href: "/safaris/tanzania", label: "Tanzania Safaris" },
                    { href: "/safaris/uganda", label: "Uganda Safaris" },
                    { href: "/safaris/rwanda", label: "Rwanda Gorilla Trekking" },
                ],
            },
            {
                label: "By Style",
                items: [
                    { href: "/safaris/luxury", label: "Luxury Safaris" },
                    { href: "/safaris/family", label: "Family Safaris" },
                    { href: "/safaris/honeymoon", label: "Honeymoon Safaris" },
                    { href: "/safaris/group", label: "Group Safaris" },
                ],
            },
        ],
        // "View all" is rendered from item.href in the dropdown footer — no duplicate entry needed.
    },

    {
        href: "/destinations",
        label: "Destinations",
        groups: [
            {
                label: "By Country",
                items: [
                    { href: "/destinations/kenya", label: "Kenya" },
                    { href: "/destinations/tanzania", label: "Tanzania" },
                    { href: "/destinations/uganda", label: "Uganda" },
                    { href: "/destinations/rwanda", label: "Rwanda" },
                ],
            },
            {
                label: "By Place",
                items: [
                    { href: "/destinations/zanzibar", label: "Zanzibar" },
                    { href: "/destinations/maasai-mara", label: "Maasai Mara" },
                    { href: "/destinations/serengeti", label: "Serengeti" },
                    { href: "/destinations/diani", label: "Diani Beach" },
                ],
            },
        ],
    },

    // Hotels, Experiences, Plan Your Trip, About, Contact — unchanged for now (flat `children`).
    {
        href: "/hotels",
        label: "Hotels",
        children: [
            { href: "/hotels/luxury", label: "Luxury Resorts" },
            { href: "/hotels/beach", label: "Beach Hotels" },
            { href: "/hotels/lodges", label: "Safari Lodges" },
            { href: "/hotels/city", label: "City Hotels" },
            { href: "/hotels/family", label: "Family Resorts" },
            { href: "/hotels/budget", label: "Budget Stays" },
            { href: "/hotels", label: "All Hotels" },
        ],
    },
    {
        href: "/experiences",
        label: "Experiences",
        children: [
            { href: "/experiences/gorilla-trekking", label: "Gorilla Trekking" },
            { href: "/experiences/game-drives", label: "Game Drives" },
            { href: "/experiences/beach-holidays", label: "Beach Holidays" },
            { href: "/experiences/cultural-tours", label: "Cultural Tours" },
            { href: "/experiences/hiking", label: "Mountain Hiking" },
            { href: "/experiences/boat-cruises", label: "Boat Cruises" },
            { href: "/experiences/day-trips", label: "Day Trips" },
            { href: "/experiences", label: "All Experiences" },
        ],
    },
    {
        href: "/plan-your-trip",
        label: "Plan Your Trip",
        children: [
            { href: "/visa-information", label: "Visa Information" },
            { href: "/travel-guide", label: "Travel Guide" },
            { href: "/best-time-to-visit", label: "Best Time to Visit" },
            { href: "/packing-list", label: "Packing Lists" },
            { href: "/faq", label: "Frequently Asked Questions" },
            { href: "/travel-insurance", label: "Travel Insurance" },
        ],
    },
    {
        href: "/about",
        label: "About",
        children: [
            { href: "/about", label: "Our Story" },
            { href: "/about/team", label: "Meet the Team" },
            { href: "/about/guides", label: "Local Guides" },
            { href: "/testimonials", label: "Guest Reviews" },
            { href: "/sustainability", label: "Sustainability" },
        ],
    },
    {
        href: "/contact",
        label: "Contact",
        children: [
            { href: "/contact", label: "Contact Us" },
            { href: "/enquiry", label: "Custom Trip Enquiry" },
            { href: "/support", label: "Customer Support" },
            { href: "/whatsapp", label: "WhatsApp Us" },
        ],
    },
];