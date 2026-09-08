"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { motion, AnimatePresence } from "framer-motion";
import { ChevronDown } from "lucide-react";
import { useState } from "react";

import type { NAV_LINKS } from "@/lib/nav-links";
import {NavItem} from "@/types/nav";

interface Props {
    links: NavItem[];
}

function allChildHrefs(item: NavItem): string[] {
    if (item.groups) {
        return item.groups.flatMap((group) => group.items.map((i) => i.href));
    }
    return item.children?.map((c) => c.href) ?? [];
}

export function DesktopNav({ links }: Props) {
    const pathname = usePathname();
    const [openMenu, setOpenMenu] = useState<string | null>(null);

    function isActive(item: NavItem) {
        if (pathname === item.href) return true;
        return allChildHrefs(item).some((href) => pathname.startsWith(href));
    }

    return (
        <nav aria-label="Main navigation" className="hidden items-center gap-8 lg:flex">
            {links.map((item) => {
                const active = isActive(item);
                const hasDropdown =
                    (item.groups && item.groups.length > 0) ||
                    (item.children && item.children.length > 0);

                if (!hasDropdown) {
                    return (
                        <Link key={item.href} href={item.href} className="relative py-2 text-sm font-medium">
                            <span
                                className={
                                    active
                                        ? "text-foreground"
                                        : "text-muted-foreground transition-colors hover:text-foreground"
                                }
                            >
                                {item.label}
                            </span>
                            {active && (
                                <motion.div
                                    layoutId="navbar-active"
                                    className="absolute -bottom-1 left-0 right-0 h-0.5 rounded-full bg-orange-500"
                                />
                            )}
                        </Link>
                    );
                }

                return (
                    <div
                        key={item.href}
                        className="relative"
                        onMouseEnter={() => setOpenMenu(item.label)}
                        onMouseLeave={() => setOpenMenu(null)}
                    >
                        <button type="button" className="flex items-center gap-1 py-2 text-sm font-medium">
                            <span
                                className={
                                    active
                                        ? "text-foreground"
                                        : "text-muted-foreground transition-colors hover:text-foreground"
                                }
                            >
                                {item.label}
                            </span>
                            <ChevronDown
                                className={`h-4 w-4 transition-transform ${
                                    openMenu === item.label ? "rotate-180" : ""
                                }`}
                            />
                        </button>

                        {active && (
                            <motion.div
                                layoutId="navbar-active"
                                className="absolute -bottom-1 left-0 right-0 h-0.5 rounded-full bg-orange-500"
                            />
                        )}

                        <AnimatePresence>
                            {openMenu === item.label && (
                                <motion.div
                                    initial={{ opacity: 0, y: 8 }}
                                    animate={{ opacity: 1, y: 0 }}
                                    exit={{ opacity: 0, y: 8 }}
                                    transition={{ duration: 0.18 }}
                                    className={`absolute left-0 top-full z-50 mt-2 overflow-hidden rounded-2xl border border-border/60 bg-background/95 backdrop-blur-xl shadow-xl ${
                                        item.groups ? "min-w-[440px]" : "min-w-[220px]"
                                    }`}
                                >
                                    {item.groups ? (
                                        <div className="grid grid-cols-2 gap-1 p-3">
                                            {item.groups.map((group) => (
                                                <div key={group.label} className="p-1">
                                                    <p className="px-3 pb-1 pt-2 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground/70">
                                                        {group.label}
                                                    </p>

                                                    {group.items.map((child) => {
                                                        const childActive = pathname === child.href;
                                                        return (
                                                            <Link
                                                                key={child.href}
                                                                href={child.href}
                                                                className={`block rounded-xl px-3 py-2 text-sm transition-colors ${
                                                                    childActive
                                                                        ? "bg-accent text-accent-foreground"
                                                                        : "text-muted-foreground hover:bg-muted hover:text-foreground"
                                                                }`}
                                                            >
                                                                {child.label}
                                                            </Link>
                                                        );
                                                    })}
                                                </div>
                                            ))}

                                            <Link
                                                href={item.href}
                                                className="col-span-2 mt-1 block rounded-xl border-t px-3 pt-3 pb-1 text-center text-xs font-medium text-orange-600 hover:text-orange-700"
                                            >
                                                View all {item.label.toLowerCase()} →
                                            </Link>
                                        </div>
                                    ) : (
                                        <div className="p-1">
                                            {item.children?.map((child) => {
                                                const childActive = pathname === child.href;
                                                return (
                                                    <Link
                                                        key={child.href}
                                                        href={child.href}
                                                        className={`block rounded-xl px-4 py-3 text-sm transition-colors ${
                                                            childActive
                                                                ? "bg-accent text-accent-foreground"
                                                                : "text-muted-foreground hover:bg-muted hover:text-foreground"
                                                        }`}
                                                    >
                                                        {child.label}
                                                    </Link>
                                                );
                                            })}
                                        </div>
                                    )}
                                </motion.div>
                            )}
                        </AnimatePresence>
                    </div>
                );
            })}
        </nav>
    );
}