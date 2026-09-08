"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter, usePathname } from "next/navigation";
import Link from "next/link";
import {
  Compass,
  MapPin,
  Calendar,
  User,
  LogOut,
  Menu,
  Bell,
} from "lucide-react";
import { toast } from "sonner";

import { useAuthStore } from "@/store/auth-store";
import { authApi } from "@/lib/auth-api";

import { Button } from "@/components/ui/button";
import {
  Avatar,
  AvatarFallback,
  AvatarImage,
} from "@/components/ui/avatar";

import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet";

const NAV_ITEMS = [
  {
    href: "/tours",
    label: "Tours",
    icon: MapPin,
  },
  {
    href: "/bookings",
    label: "My Bookings",
    icon: Calendar,
  },
  {
    href: "/profile",
    label: "My Profile",
    icon: User,
  },
];

export default function CustomerLayout({
                                         children,
                                       }: {
  children: React.ReactNode;
}) {
  const router = useRouter();
  const pathname = usePathname();

  const {
    isAuthenticated,
    accessToken,
    user,
    clearSession,
  } = useAuthStore();

  const redirected = useRef(false);

  const [hasHydrated, setHasHydrated] = useState(() =>
      useAuthStore.persist.hasHydrated()
  );

  const [mobileNavOpen, setMobileNavOpen] = useState(false);

  /*
   * ------------------------------------------------------------
   * Zustand persistence hydration
   * ------------------------------------------------------------
   */
  useEffect(() => {
    const unsubscribe =
        useAuthStore.persist.onFinishHydration(() => {
          setHasHydrated(true);
        });

    setHasHydrated(useAuthStore.persist.hasHydrated());

    return unsubscribe;
  }, []);

  /*
   * ------------------------------------------------------------
   * Authentication guard
   * ------------------------------------------------------------
   */
  useEffect(() => {
    if (!hasHydrated) return;

    if (!isAuthenticated || !accessToken) {
      const timeout = setTimeout(() => {
        const store = useAuthStore.getState();

        if (!store.isAuthenticated || !store.accessToken) {
          if (!redirected.current) {
            redirected.current = true;
            router.replace("/login");
          }
        }
      }, 0);

      return () => clearTimeout(timeout);
    }

    redirected.current = false;
  }, [
    hasHydrated,
    isAuthenticated,
    accessToken,
    router,
  ]);

  /*
   * ------------------------------------------------------------
   * Logout
   * ------------------------------------------------------------
   */
  async function handleLogout() {
    try {
      await authApi.logout();
    } catch {
      // Backend logout failure should not prevent local logout.
    } finally {
      clearSession();

      toast.success("Signed out");

      window.location.href = "/login";
    }
  }

  /*
   * ------------------------------------------------------------
   * Loading / unauthenticated state
   * ------------------------------------------------------------
   */
  if (!hasHydrated || !isAuthenticated || !accessToken) {
    return (
        <div className="flex min-h-screen flex-col items-center justify-center gap-4 bg-dust">
          <div className="flex h-12 w-12 items-center justify-center rounded-full bg-savanna/10">
            <Compass
                className="h-6 w-6 animate-pulse text-savanna"
                strokeWidth={1.75}
            />
          </div>

          <div className="text-center">
            <p className="font-display text-sm font-medium text-earth">
              Damuchi Safaris
            </p>

            <p className="mt-0.5 text-xs text-stone">
              Checking your session…
            </p>
          </div>
        </div>
    );
  }

  /*
   * ------------------------------------------------------------
   * User helpers
   * ------------------------------------------------------------
   */
  const displayName =
      user?.displayName ||
      user?.email ||
      "Account";

  const firstName =
      user?.displayName?.split(" ")[0] ||
      "Profile";

  const initials = user?.displayName
      ? user.displayName
          .split(" ")
          .filter(Boolean)
          .map((part) => part[0])
          .slice(0, 2)
          .join("")
          .toUpperCase()
      : user?.email?.[0]?.toUpperCase() || "?";

  const isActive = (href: string) =>
      pathname === href ||
      pathname.startsWith(`${href}/`);

  return (
      <div className="flex min-h-screen flex-col bg-dust">
        {/* ======================================================
          HEADER
          ====================================================== */}
        <header className="sticky top-0 z-40 border-b border-border bg-dust/90 backdrop-blur-xl">
          <div className="mx-auto flex h-16 w-full max-w-7xl items-center justify-between px-4 sm:px-6">
            {/* Brand */}
            <Link
                href="/tours"
                className="group flex items-center gap-2.5"
            >
              <div className="flex h-9 w-9 items-center justify-center rounded-full bg-savanna/10 text-savanna transition-transform duration-200 group-hover:scale-105">
                <Compass
                    className="h-4.5 w-4.5"
                    strokeWidth={1.75}
                />
              </div>

              <span className="font-display text-lg font-semibold tracking-tight text-earth sm:text-xl">
              Damuchi{" "}
                <span className="text-savanna">
                Safaris
              </span>
            </span>
            </Link>

            {/* ==================================================
              DESKTOP NAVIGATION
              ================================================== */}
            <nav className="hidden items-center gap-1 sm:flex">
              {NAV_ITEMS.map(
                  ({ href, label, icon: Icon }) => {
                    const active = isActive(href);

                    return (
                        <Link
                            key={href}
                            href={href}
                            aria-current={
                              active ? "page" : undefined
                            }
                            className={[
                              "flex items-center gap-1.5",
                              "rounded-full px-3.5 py-2",
                              "text-sm font-medium",
                              "transition-all duration-200",
                              "focus-visible:outline-none",
                              "focus-visible:ring-2",
                              "focus-visible:ring-savanna/40",
                              active
                                  ? "bg-savanna/10 text-savanna"
                                  : "text-stone hover:bg-earth/5 hover:text-earth",
                            ].join(" ")}
                        >
                          <Icon className="h-4 w-4" />
                          {label}
                        </Link>
                    );
                  }
              )}

              <div className="mx-1.5 h-5 w-px bg-border" />

              {/* User menu */}
              <DropdownMenu>
                <DropdownMenuTrigger
                    className={[
                      "flex items-center gap-2",
                      "rounded-full py-1 pl-1 pr-3",
                      "outline-none transition-colors",
                      "hover:bg-earth/5",
                      "focus-visible:ring-2",
                      "focus-visible:ring-savanna/40",
                    ].join(" ")}
                >
                  <Avatar className="h-7 w-7">
                    {user?.profilePhotoUrl && (
                        <AvatarImage
                            src={user.profilePhotoUrl}
                            alt={displayName}
                        />
                    )}

                    <AvatarFallback className="bg-savanna/10 text-[11px] font-semibold text-savanna">
                      {initials}
                    </AvatarFallback>
                  </Avatar>

                  <span className="max-w-28 truncate text-sm font-medium text-earth">
                  {firstName}
                </span>
                </DropdownMenuTrigger>

                <DropdownMenuContent
                    align="end"
                    sideOffset={8}
                    className="w-56"
                >
                  <DropdownMenuLabel>
                    <p className="truncate font-medium text-earth">
                      {displayName}
                    </p>

                    <p className="mt-0.5 truncate text-xs font-normal text-stone">
                      {user?.email}
                    </p>
                  </DropdownMenuLabel>

                  <DropdownMenuSeparator />

                  <DropdownMenuItem
                      onSelect={() =>
                          router.push("/profile")
                      }
                  >
                    <User className="h-4 w-4" />
                    My profile
                  </DropdownMenuItem>

                  <DropdownMenuItem
                      onSelect={() =>
                          router.push("/bookings")
                      }
                  >
                    <Calendar className="h-4 w-4" />
                    My bookings
                  </DropdownMenuItem>

                  <DropdownMenuItem
                      onSelect={() =>
                          router.push("/notifications")
                      }
                  >
                    <Bell className="h-4 w-4" />
                    Notifications
                  </DropdownMenuItem>

                  <DropdownMenuSeparator />

                  <DropdownMenuItem
                      onSelect={handleLogout}
                      className="text-destructive focus:bg-destructive/10 focus:text-destructive"
                  >
                    <LogOut className="h-4 w-4" />
                    Sign out
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </nav>

            {/* ==================================================
              MOBILE NAVIGATION
              ================================================== */}
            <Sheet
                open={mobileNavOpen}
                onOpenChange={setMobileNavOpen}
            >
              <SheetTrigger asChild>
                <Button
                    variant="ghost"
                    size="icon"
                    className="rounded-full sm:hidden"
                    aria-label="Open navigation"
                >
                  <Menu className="h-5 w-5 text-earth" />
                </Button>
              </SheetTrigger>

              <SheetContent
                  side="right"
                  className="w-[min(20rem,85vw)] bg-dust px-4"
              >
                <SheetHeader className="sr-only">
                  <SheetTitle>
                    Customer navigation
                  </SheetTitle>
                </SheetHeader>

                {/* User card */}
                <div className="mt-6 flex items-center gap-3 rounded-2xl border border-savanna/10 bg-savanna/5 p-3.5">
                  <Avatar className="h-10 w-10 shrink-0">
                    {user?.profilePhotoUrl && (
                        <AvatarImage
                            src={user.profilePhotoUrl}
                            alt={displayName}
                        />
                    )}

                    <AvatarFallback className="bg-savanna/10 font-semibold text-savanna">
                      {initials}
                    </AvatarFallback>
                  </Avatar>

                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium text-earth">
                      {displayName}
                    </p>

                    <p className="truncate text-xs text-stone">
                      {user?.email}
                    </p>
                  </div>
                </div>

                {/* Navigation */}
                <nav className="mt-6 space-y-1">
                  {NAV_ITEMS.map(
                      ({ href, label, icon: Icon }) => {
                        const active = isActive(href);

                        return (
                            <Link
                                key={href}
                                href={href}
                                onClick={() =>
                                    setMobileNavOpen(false)
                                }
                                aria-current={
                                  active ? "page" : undefined
                                }
                                className={[
                                  "flex items-center gap-3",
                                  "rounded-xl px-3 py-3",
                                  "text-sm font-medium",
                                  "transition-colors",
                                  active
                                      ? "bg-savanna/10 text-savanna"
                                      : "text-stone hover:bg-earth/5 hover:text-earth",
                                ].join(" ")}
                            >
                              <Icon className="h-4 w-4" />
                              {label}
                            </Link>
                        );
                      }
                  )}
                </nav>

                {/* Account actions */}
                <div className="mt-6 border-t border-border pt-4">
                  <Link
                      href="/notifications"
                      onClick={() =>
                          setMobileNavOpen(false)
                      }
                      className="flex items-center gap-3 rounded-xl px-3 py-3 text-sm font-medium text-stone transition-colors hover:bg-earth/5 hover:text-earth"
                  >
                    <Bell className="h-4 w-4" />
                    Notifications
                  </Link>

                  <button
                      type="button"
                      onClick={handleLogout}
                      className="flex w-full items-center gap-3 rounded-xl px-3 py-3 text-sm font-medium text-destructive transition-colors hover:bg-destructive/10"
                  >
                    <LogOut className="h-4 w-4" />
                    Sign out
                  </button>
                </div>
              </SheetContent>
            </Sheet>
          </div>

          {/* Damuchi horizon rule */}
          <div className="h-0.5 bg-savanna" />
        </header>

        {/* ======================================================
          PAGE CONTENT
          ====================================================== */}
        <main className="mx-auto min-w-0 w-full max-w-7xl flex-1 px-4 py-8 sm:px-6">
          {children}
        </main>

        {/* ======================================================
          FOOTER
          ====================================================== */}
        <footer className="border-t border-border bg-dust">
          <div className="mx-auto flex max-w-7xl flex-col items-center justify-between gap-3 px-4 py-6 text-xs text-stone sm:flex-row sm:px-6">
            <p>
              © {new Date().getFullYear()} Damuchi
              Safaris. All rights reserved.
            </p>

            <nav className="flex items-center gap-4">
              <Link
                  href="/tours"
                  className="transition-colors hover:text-earth"
              >
                Tours
              </Link>

              <Link
                  href="/bookings"
                  className="transition-colors hover:text-earth"
              >
                Bookings
              </Link>

              <Link
                  href="/profile"
                  className="transition-colors hover:text-earth"
              >
                Profile
              </Link>
            </nav>
          </div>
        </footer>
      </div>
  );
}