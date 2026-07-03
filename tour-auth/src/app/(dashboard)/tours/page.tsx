"use client"
import { MapPin, Plus } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"

export default function ToursPage() {
  return (
    <div className="space-y-6 animate-fade-up">
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2">
            <MapPin className="w-5 h-5 text-[#C9742F]" />
            <h2 className="font-display text-xl font-semibold">Tours</h2>
          </div>
          <p className="text-sm text-muted-foreground mt-1">Manage your tour catalogue</p>
        </div>
        <Button variant="clay" size="sm" className="gap-1.5">
          <Plus className="w-3.5 h-3.5" /> New tour
        </Button>
      </div>

      <Card>
        <CardContent className="pt-12 pb-12 flex flex-col items-center gap-3">
          <MapPin className="w-10 h-10 text-muted-foreground" strokeWidth={1.5} />
          <p className="font-medium text-sm">No tours yet</p>
          <p className="text-xs text-muted-foreground">Your tour catalogue will appear here once added.</p>
          <Button variant="clay" size="sm" className="mt-2 gap-1.5">
            <Plus className="w-3.5 h-3.5" /> Create first tour
          </Button>
        </CardContent>
      </Card>
    </div>
  )
}
