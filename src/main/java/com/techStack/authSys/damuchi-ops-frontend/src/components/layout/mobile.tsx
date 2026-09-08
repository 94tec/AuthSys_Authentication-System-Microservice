"use client";

import { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { ChevronDown, Heart, LogOut, MessagesSquare, PhoneCall, User as UserIcon } from "lucide-react";

import {
    Sheet,
    SheetContent,
    SheetHeader,
    SheetTitle,
} from "@/components/ui/sheet";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import type { VisitorStatus } from "@/hooks/use-visitor";
import { EnquiryModal } from "@/components/landing/enquiry/enquiry-modal";
//import type { NavItem } from "@/lib/nav-links";
import {NavItem} from "@/types/nav";

interface MobileNavProps {
    open: boolean;
    onOpenChange: (open: boolean) => void;
    navLinks: NavItem[];
    visitorStatus: VisitorStatus;
    firstName?: string;
    onLogout: () => void;
}

export function MobileNav({
                              open,
                              onOpenChange,
                              navLinks,
                              visitorStatus,
                              firstName,
                              onLogout,
                          }: MobileNavProps) {
    const pathname = usePathname();
    const [expanded, setExpanded] = useState<string | null>(null);

    function close() {
        onOpenChange(false);
        setExpanded(null);
    }

    const isLoading = visitorStatus === "loading";
    const isCustomer = visitorStatus === "customer";

    return (
        <Sheet open={open} onOpenChange={onOpenChange}>
            <SheetContent side="right" className="flex w-[85%] max-w-sm flex-col overflow-y-auto">
                <SheetHeader>
                    <SheetTitle className="font-display text-lg">
                        Damuchi <span className="text-coral">Safaris</span>
                    </SheetTitle>
                </SheetHeader>

                {isLoading ? (
                    <div className="mt-2 flex items-center gap-3 rounded-xl bg-gray-50 p-3">
                        <div className="h-9 w-9 animate-pulse rounded-full bg-gray-200" />
                        <div className="space-y-1.5">
                            <div className="h-3 w-20 animate-pulse rounded bg-gray-200" />
                            <div className="h-2.5 w-14 animate-pulse rounded bg-gray-200" />
                        </div>
                    </div>
                ) : isCustomer && firstName ? (
                    <div className="mt-2 flex items-center gap-3 rounded-xl bg-coral/5 p-3">
                        <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-coral to-orange text-sm font-semibold text-white">
                            {firstName[0]?.toUpperCase()}
                        </span>
                        <div className="min-w-0">
                            <p className="truncate text-sm font-medium text-gray-900">{firstName}</p>
                            <p className="text-xs text-gray-500">Welcome back</p>
                        </div>
                    </div>
                ) : null}

                <nav className="mt-6 flex flex-1 flex-col gap-1" aria-label="Mobile navigation">
                    {navLinks.map((link) => {
                        const isActive = pathname === link.href || pathname?.startsWith(`${link.href}/`);
                        const hasDropdown =
                            (link.groups && link.groups.length > 0) ||
                            (link.children && link.children.length > 0);
                        const isExpanded = expanded === link.label;

                        if (!hasDropdown) {
                            return (
                                <Link
                                    key={link.href}
                                    href={link.href}
                                    onClick={close}
                                    aria-current={isActive ? "page" : undefined}
                                    className={cn(
                                        "rounded-lg px-3 py-2.5 text-sm font-medium transition-colors",
                                        isActive ? "bg-coral/10 text-coral" : "text-gray-700 hover:bg-gray-50"
                                    )}
                                >
                                    {link.label}
                                </Link>
                            );
                        }

                        return (
                            <div key={link.href}>
                                <button
                                    type="button"
                                    onClick={() => setExpanded(isExpanded ? null : link.label)}
                                    aria-expanded={isExpanded}
                                    className={cn(
                                        "flex w-full items-center justify-between rounded-lg px-3 py-2.5 text-sm font-medium transition-colors",
                                        isActive ? "bg-coral/10 text-coral" : "text-gray-700 hover:bg-gray-50"
                                    )}
                                >
                                    {link.label}
                                    <ChevronDown
                                        className={cn("h-4 w-4 transition-transform", isExpanded && "rotate-180")}
                                    />
                                </button>

                                {isExpanded && (
                                    <div className="ml-2 mt-1 space-y-3 border-l border-gray-100 pl-3">
                                        {link.groups
                                            ? link.groups.map((group) => (
                                                <div key={group.label}>
                                                    <p className="px-3 pb-1 text-[11px] font-semibold uppercase tracking-wide text-gray-400">
                                                        {group.label}
                                                    </p>
                                                    {group.items.map((child) => (
                                                        <Link
                                                            key={child.href}
                                                            href={child.href}
                                                            onClick={close}
                                                            className="block rounded-lg px-3 py-2 text-sm text-gray-600 hover:bg-gray-50"
                                                        >
                                                            {child.label}
                                                        </Link>
                                                    ))}
                                                </div>
                                            ))
                                            : link.children?.map((child) => (
                                                <Link
                                                    key={child.href}
                                                    href={child.href}
                                                    onClick={close}
                                                    className="block rounded-lg px-3 py-2 text-sm text-gray-600 hover:bg-gray-50"
                                                >
                                                    {child.label}
                                                </Link>
                                            ))}

                                        <Link
                                            href={link.href}
                                            onClick={close}
                                            className="block rounded-lg px-3 py-2 text-sm font-medium text-orange-600"
                                        >
                                            View all {link.label.toLowerCase()} →
                                        </Link>
                                    </div>
                                )}
                            </div>
                        );
                    })}

                    {isCustomer && (
                        <>
                            <div className="my-2 border-t border-gray-100" />
                            <Link
                                href="/enquiries"
                                onClick={close}
                                className="flex items-center gap-2 rounded-lg px-3 py-2.5 text-sm font-medium text-gray-700 transition-colors hover:bg-gray-50"
                            >
                                <MessagesSquare className="h-4 w-4 text-coral" /> My Enquiries
                            </Link>
                            <Link
                                href="/wishlist"
                                onClick={close}
                                className="flex items-center gap-2 rounded-lg px-3 py-2.5 text-sm font-medium text-gray-700 transition-colors hover:bg-gray-50"
                            >
                                <Heart className="h-4 w-4 text-coral" /> Saved Tours
                            </Link>
                            <Link
                                href="/profile"
                                onClick={close}
                                className="flex items-center gap-2 rounded-lg px-3 py-2.5 text-sm font-medium text-gray-700 transition-colors hover:bg-gray-50"
                            >
                                <UserIcon className="h-4 w-4 text-coral" /> Profile
                            </Link>
                        </>
                    )}
                </nav>

                <div className="mt-auto space-y-3 border-t border-gray-100 pt-4">

                    <a href="tel:+254700000000"
                        className="flex items-center justify-center gap-1.5 rounded-lg py-2 text-sm font-medium text-gray-600 transition-colors hover:bg-gray-50 hover:text-gray-900"
                    >
                        <PhoneCall className="h-4 w-4" /> +254 700 000 000
                    </a>
                </div>

            {isLoading ? (
                <div className="h-10 w-full animate-pulse rounded-lg bg-gray-100" />
            ) : isCustomer ? (
                <Button
                    variant="outline"
                    className="w-full text-red-600 hover:bg-red-50 hover:text-red-700"
                    onClick={() => {
                        onLogout();
                        close();
                    }}
                >
                    <LogOut className="h-4 w-4" /> Sign out
                </Button>
            ) : (
                <Link href="/auth/login" onClick={close}>
                    <Button variant="outline" className="w-full">Sign in</Button>
                </Link>
            )}

            <EnquiryModal source="mobile-drawer">
                <Button variant="accent" className="w-full" onClick={close}>
                    Make an Enquiry
                </Button>
            </EnquiryModal>
        </SheetContent>
</Sheet>
);
}