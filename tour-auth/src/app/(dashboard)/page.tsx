"use client"
import { useAuthStore } from "@/lib/stores/auth.store"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { MapPin, Users, Calendar, TrendingUp } from "lucide-react"

const STATS = [
  { label: "Active Tours",     value: "12",  icon: MapPin,      delta: "+2 this month" },
  { label: "Staff Members",    value: "24",  icon: Users,       delta: "3 pending approval" },
  { label: "Upcoming Trips",   value: "7",   icon: Calendar,    delta: "Next: 3 days" },
  { label: "Bookings (MTD)",   value: "89",  icon: TrendingUp,  delta: "+14% vs last month" },
]

export default function DashboardPage() {
  const { user } = useAuthStore()

  return (
    <div className="space-y-6 animate-fade-up">
      {/* Welcome */}
      <div>
        <h2 className="font-display text-2xl font-semibold">
          Good {getTimeOfDay()}, {user?.firstName} 👋
        </h2>
        <p className="text-sm text-muted-foreground mt-1">
          Here's what's happening at Venture Tours today.
        </p>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        {STATS.map(({ label, value, icon: Icon, delta }) => (
          <Card key={label}>
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">{label}</CardTitle>
              <Icon className="w-4 h-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <p className="font-display text-3xl font-bold">{value}</p>
              <p className="text-xs text-muted-foreground mt-1">{delta}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Role badge */}
      <div className="flex items-center gap-2">
        <span className="text-sm text-muted-foreground">Your access level:</span>
        <Badge variant={user?.role === "ADMIN" ? "clay" : "moss"}>{user?.role}</Badge>
      </div>
    </div>
  )
}

function getTimeOfDay() {
  const h = new Date().getHours()
  if (h < 12) return "morning"
  if (h < 17) return "afternoon"
  return "evening"
}
