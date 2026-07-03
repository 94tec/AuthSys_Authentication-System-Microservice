"use client"
import { useState, useEffect, useCallback } from "react"
import { toast } from "sonner"
import { Shield, RefreshCw } from "lucide-react"

import { ApprovalCard } from "@/components/dashboard/approval-card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { adminApi } from "@/lib/api/admin"
import type { PendingUser } from "@/types"

export default function PendingApprovalsPage() {
  const [users, setUsers] = useState<PendingUser[]>([])
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)

  const fetchUsers = useCallback(async (silent = false) => {
    if (!silent) setLoading(true)
    else setRefreshing(true)
    try {
      const res = await adminApi.getPendingUsers()
      setUsers(res.data)
    } catch (err: any) {
      toast.error("Couldn't load pending approvals.")
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [])

  useEffect(() => { fetchUsers() }, [fetchUsers])

  return (
    <div className="space-y-6 animate-fade-up">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-[#C9742F]" />
            <h2 className="font-display text-xl font-semibold">Pending Approvals</h2>
            {users.length > 0 && (
              <Badge variant="clay">{users.length}</Badge>
            )}
          </div>
          <p className="text-sm text-muted-foreground mt-1">
            Review and action staff account requests
          </p>
        </div>
        <Button
          size="sm"
          variant="outline"
          onClick={() => fetchUsers(true)}
          loading={refreshing}
          className="gap-1.5"
        >
          <RefreshCw className="w-3.5 h-3.5" /> Refresh
        </Button>
      </div>

      {/* Content */}
      {loading ? (
        <div className="grid gap-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="h-20 rounded-xl bg-muted animate-pulse" />
          ))}
        </div>
      ) : users.length === 0 ? (
        <div className="rounded-xl border border-dashed border-border p-12 text-center">
          <Shield className="w-8 h-8 text-muted-foreground mx-auto mb-3" strokeWidth={1.5} />
          <p className="font-medium text-sm">No pending requests</p>
          <p className="text-xs text-muted-foreground mt-1">New account requests will appear here</p>
        </div>
      ) : (
        <div className="grid gap-3">
          {users.map((user) => (
            <ApprovalCard key={user.id} user={user} onAction={() => fetchUsers(true)} />
          ))}
        </div>
      )}
    </div>
  )
}
