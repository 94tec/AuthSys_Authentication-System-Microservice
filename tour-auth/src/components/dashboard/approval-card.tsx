"use client"
import { useState } from "react"
import { toast } from "sonner"
import { UserCheck, UserX, Clock } from "lucide-react"

import { Card, CardContent } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import {
  AlertDialog, AlertDialogContent, AlertDialogHeader, AlertDialogTitle,
  AlertDialogDescription, AlertDialogFooter, AlertDialogAction, AlertDialogCancel,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog"
import { adminApi } from "@/lib/api/admin"
import { formatDate } from "@/lib/utils"
import type { PendingUser } from "@/types"

interface ApprovalCardProps {
  user: PendingUser
  onAction: () => void
}

export function ApprovalCard({ user, onAction }: ApprovalCardProps) {
  const [approving, setApproving] = useState(false)
  const [rejectReason, setRejectReason] = useState("")

  const handleApprove = async () => {
    setApproving(true)
    try {
      await adminApi.approveUser(user.id)
      toast.success(`${user.firstName} ${user.lastName} approved.`)
      onAction()
    } catch (err: any) {
      toast.error(err.message ?? "Approval failed.")
    } finally {
      setApproving(false)
    }
  }

  const handleReject = async () => {
    try {
      await adminApi.rejectUser(user.id, rejectReason || "Application not approved.")
      toast.success(`${user.firstName} ${user.lastName} rejected.`)
      onAction()
    } catch (err: any) {
      toast.error(err.message ?? "Rejection failed.")
    }
  }

  return (
    <Card className="hover:shadow-md transition-shadow">
      <CardContent className="pt-5 pb-5">
        <div className="flex items-start justify-between gap-4">
          {/* Avatar + info */}
          <div className="flex items-center gap-3 min-w-0">
            <div className="w-10 h-10 rounded-full bg-[#3D5A4C]/15 flex items-center justify-center text-sm font-bold text-[#3D5A4C] shrink-0">
              {user.firstName[0]}{user.lastName[0]}
            </div>
            <div className="min-w-0">
              <p className="font-medium text-sm">{user.firstName} {user.lastName}</p>
              <p className="text-xs text-muted-foreground truncate">{user.email}</p>
              <div className="flex items-center gap-2 mt-1">
                <Badge variant="moss" className="text-[10px]">{user.role}</Badge>
                <span className="text-[10px] text-muted-foreground flex items-center gap-1">
                  <Clock className="w-3 h-3" /> {formatDate(user.registeredAt)}
                </span>
              </div>
            </div>
          </div>

          {/* Actions */}
          <div className="flex items-center gap-2 shrink-0">
            <Button
              size="sm"
              variant="clay"
              loading={approving}
              onClick={handleApprove}
              className="gap-1.5"
            >
              <UserCheck className="w-3.5 h-3.5" /> Approve
            </Button>

            <AlertDialog>
              <AlertDialogTrigger asChild>
                <Button size="sm" variant="outline" className="gap-1.5 border-destructive/40 text-destructive hover:bg-destructive/5">
                  <UserX className="w-3.5 h-3.5" /> Reject
                </Button>
              </AlertDialogTrigger>
              <AlertDialogContent>
                <AlertDialogHeader>
                  <AlertDialogTitle>Reject {user.firstName} {user.lastName}?</AlertDialogTitle>
                  <AlertDialogDescription>
                    This will deny their access request. You can optionally provide a reason.
                  </AlertDialogDescription>
                </AlertDialogHeader>
                <textarea
                  value={rejectReason}
                  onChange={(e) => setRejectReason(e.target.value)}
                  placeholder="Reason (optional)"
                  rows={3}
                  className="w-full rounded-lg border border-input bg-card px-3 py-2 text-sm resize-none focus:outline-none focus:ring-2 focus:ring-ring"
                />
                <AlertDialogFooter>
                  <AlertDialogCancel>Cancel</AlertDialogCancel>
                  <AlertDialogAction onClick={handleReject}>Confirm rejection</AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
