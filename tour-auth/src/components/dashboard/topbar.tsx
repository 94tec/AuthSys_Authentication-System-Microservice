"use client"
import { useRouter } from "next/navigation"
import { toast } from "sonner"
import { LogOut, Settings, User } from "lucide-react"

import { useAuthStore } from "@/lib/stores/auth.store"
import { authApi } from "@/lib/api/auth"
import { getInitials } from "@/lib/utils"
import {
  DropdownMenu, DropdownMenuTrigger, DropdownMenuContent,
  DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator,
} from "@/components/ui/dropdown-menu"

interface TopbarProps {
  title?: string
}

export function Topbar({ title }: TopbarProps) {
  const router = useRouter()
  const { user, clearSession } = useAuthStore()

  const handleLogout = async () => {
    try { await authApi.logout() } catch { /* ignore */ }
    clearSession()
    router.push("/login")
    toast.success("You've been signed out.")
  }

  return (
    <header className="h-14 px-4 md:px-6 flex items-center justify-between border-b border-border bg-card/60 backdrop-blur-sm sticky top-0 z-30">
      <h1 className="font-display text-base font-semibold text-foreground">{title ?? "Dashboard"}</h1>

      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <button className="w-8 h-8 rounded-full bg-[#3D5A4C]/20 flex items-center justify-center text-xs font-bold text-[#3D5A4C] hover:bg-[#3D5A4C]/30 transition-colors focus:outline-none focus:ring-2 focus:ring-ring">
            {user ? getInitials(user.firstName, user.lastName) : "?"}
          </button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-52">
          <DropdownMenuLabel>
            {user?.firstName} {user?.lastName}
            <span className="block text-[10px] font-normal text-muted-foreground">{user?.email}</span>
          </DropdownMenuLabel>
          <DropdownMenuSeparator />
          <DropdownMenuItem onClick={() => router.push("/dashboard/settings")}>
            <Settings className="w-3.5 h-3.5" /> Settings
          </DropdownMenuItem>
          <DropdownMenuSeparator />
          <DropdownMenuItem onClick={handleLogout} className="text-destructive focus:text-destructive">
            <LogOut className="w-3.5 h-3.5" /> Sign out
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </header>
  )
}
