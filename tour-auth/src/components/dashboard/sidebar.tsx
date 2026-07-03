"use client"
import Link from "next/link"
import { usePathname } from "next/navigation"
import { cn } from "@/lib/utils"
import { useAuthStore } from "@/lib/stores/auth.store"
import {
  LayoutDashboard, Users, MapPin, Settings, Mountain, Shield,
} from "lucide-react"

const NAV = [
  { href: "/dashboard",                  icon: LayoutDashboard, label: "Overview",        roles: ["ADMIN","MANAGER","STAFF","GUIDE"] },
  { href: "/dashboard/admin/pending-approvals", icon: Shield, label: "Approvals",    roles: ["ADMIN"] },
  { href: "/dashboard/tours",            icon: MapPin,          label: "Tours",           roles: ["ADMIN","MANAGER","STAFF","GUIDE"] },
  { href: "/dashboard/settings",         icon: Settings,        label: "Settings",         roles: ["ADMIN","MANAGER","STAFF","GUIDE"] },
] as const

export function Sidebar() {
  const pathname = usePathname()
  const { user } = useAuthStore()

  const visible = NAV.filter((n) => user?.role && (n.roles as readonly string[]).includes(user.role))

  return (
    <aside className="hidden md:flex flex-col w-56 shrink-0 bg-card border-r border-border min-h-screen">
      {/* Brand */}
      <div className="flex items-center gap-2.5 px-4 py-5 border-b border-border">
        <div className="w-8 h-8 rounded-lg bg-[#C9742F] flex items-center justify-center shrink-0">
          <Mountain className="w-4 h-4 text-white" strokeWidth={2} />
        </div>
        <span className="font-display text-sm font-semibold text-foreground">Venture Tours</span>
      </div>

      {/* Nav */}
      <nav className="flex flex-col gap-0.5 p-3 flex-1">
        {visible.map(({ href, icon: Icon, label }) => {
          const active = pathname === href || (href !== "/dashboard" && pathname.startsWith(href))
          return (
            <Link
              key={href}
              href={href}
              className={cn(
                "flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm font-medium transition-all",
                active
                  ? "bg-[#C9742F]/10 text-[#C9742F]"
                  : "text-muted-foreground hover:bg-muted hover:text-foreground"
              )}
            >
              <Icon className="w-4 h-4 shrink-0" />
              {label}
            </Link>
          )
        })}
      </nav>

      {/* Role pill */}
      <div className="p-3 border-t border-border">
        <div className="flex items-center gap-2 px-3 py-2">
          <div className="w-7 h-7 rounded-full bg-[#3D5A4C]/20 flex items-center justify-center text-xs font-bold text-[#3D5A4C]">
            {user?.firstName?.[0]}{user?.lastName?.[0]}
          </div>
          <div className="min-w-0">
            <p className="text-xs font-medium truncate">{user?.firstName} {user?.lastName}</p>
            <p className="text-[10px] text-muted-foreground">{user?.role}</p>
          </div>
        </div>
      </div>
    </aside>
  )
}
