"use client";

import Link from "next/link";
import {
    Bell,
    LayoutDashboard,
    LogOut,
    Settings,
    User,
} from "lucide-react";

import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuSeparator,
    DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

interface Props {
    firstName: string;
    email?: string;
    initials: string;
    onLogout: () => Promise<void>;
}

export function UserMenu({
                             firstName,
                             email,
                             initials,
                             onLogout,
                         }: Props) {
    return (
        <DropdownMenu>
            <DropdownMenuTrigger asChild>
                <button
                    aria-label="Account menu"
                    className="
                        flex items-center gap-2
                        rounded-full
                        border border-border/60
                        bg-background/80
                        p-1.5
                        backdrop-blur-sm
                        transition-all
                        hover:border-orange-500/30
                        hover:shadow-md
                        focus:outline-none
                        focus:ring-2
                        focus:ring-orange-500/20
                    "
                >
                    <div className="flex h-8 w-8 items-center justify-center rounded-full bg-gradient-to-br from-orange-500 to-orange-600 text-xs font-semibold text-white shadow-sm">
                        {initials}
                    </div>

                    <div className="flex h-8 w-8 items-center justify-center rounded-full bg-muted">
                        <User className="h-4 w-4 text-muted-foreground" />
                    </div>
                </button>
            </DropdownMenuTrigger>

            <DropdownMenuContent
                align="end"
                sideOffset={6}
                className="w-52 p-1"
            >
                <div className="px-2.5 py-2">
                    <p className="truncate text-sm font-medium">
                        {firstName}
                    </p>

                    {email && (
                        <p className="truncate text-[11px] text-muted-foreground">
                            {email}
                        </p>
                    )}
                </div>

                <DropdownMenuSeparator />

                <DropdownMenuItem asChild className="gap-2 py-2">
                    <Link href="/dashboard">
                        <LayoutDashboard className="h-4 w-4" />
                        Dashboard
                    </Link>
                </DropdownMenuItem>

                <DropdownMenuItem asChild className="gap-2 py-2">
                    <Link href="/profile">
                        <User className="h-4 w-4" />
                        Profile
                    </Link>
                </DropdownMenuItem>

                <DropdownMenuItem asChild className="gap-2 py-2">
                    <Link href="/notifications">
                        <Bell className="h-4 w-4" />
                        Notifications
                    </Link>
                </DropdownMenuItem>

                <DropdownMenuItem asChild className="gap-2 py-2">
                    <Link href="/settings">
                        <Settings className="h-4 w-4" />
                        Settings
                    </Link>
                </DropdownMenuItem>

                <DropdownMenuSeparator />

                <DropdownMenuItem
                    onClick={onLogout}
                    className="text-destructive focus:text-destructive"
                >
                    <LogOut className="mr-2 h-4 w-4" />
                    Sign Out
                </DropdownMenuItem>
            </DropdownMenuContent>
        </DropdownMenu>
    );
}