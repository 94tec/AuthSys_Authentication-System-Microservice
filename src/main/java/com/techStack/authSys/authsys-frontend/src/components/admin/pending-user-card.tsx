"use client";

import { useState } from "react";
import { Check, X, Mail, Phone, Calendar } from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import type { PendingUser } from "@/types/auth";

interface PendingUserCardProps {
  user: PendingUser;
  isProcessing: boolean;
  onApprove: (id: string) => void;
  onReject: (id: string) => void;
}

export function PendingUserCard({
  user,
  isProcessing,
  onApprove,
  onReject,
}: PendingUserCardProps) {
  const initials = `${user.firstName?.[0] ?? ""}${user.lastName?.[0] ?? ""}`.toUpperCase();

  return (
    <div className="flex flex-col gap-4 rounded-xl border border-border bg-card p-5 transition-shadow hover:shadow-sm sm:flex-row sm:items-center sm:justify-between">
      <div className="flex items-start gap-3.5">
        <Avatar className="h-11 w-11 shrink-0">
          <AvatarFallback className="text-sm">{initials}</AvatarFallback>
        </Avatar>
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <p className="font-medium text-foreground">
              {user.firstName} {user.lastName}
            </p>
            <Badge variant="warning">Pending approval</Badge>
          </div>
          <div className="mt-1.5 flex flex-col gap-1 text-xs text-muted-foreground sm:flex-row sm:gap-4">
            <span className="flex items-center gap-1">
              <Mail className="h-3 w-3" />
              {user.email}
            </span>
            {user.phoneNumber && (
              <span className="flex items-center gap-1">
                <Phone className="h-3 w-3" />
                {user.phoneNumber}
              </span>
            )}
            <span className="flex items-center gap-1">
              <Calendar className="h-3 w-3" />
              {formatDistanceToNow(new Date(user.createdAt), { addSuffix: true })}
            </span>
          </div>
          <div className="mt-2 flex flex-wrap gap-1.5">
            {user.roles.map((role) => (
              <Badge key={role} variant="secondary" className="text-[10px]">
                {role}
              </Badge>
            ))}
          </div>
        </div>
      </div>

      <div className="flex shrink-0 gap-2">
        <AlertDialog>
          <AlertDialogTrigger asChild>
            <Button variant="outline" size="sm" disabled={isProcessing}>
              <X className="h-3.5 w-3.5" />
              Reject
            </Button>
          </AlertDialogTrigger>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>Reject this access request?</AlertDialogTitle>
              <AlertDialogDescription>
                <strong>{user.firstName} {user.lastName}</strong> ({user.email}) will
                not be able to sign in. This action is logged in the audit trail.
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel>Cancel</AlertDialogCancel>
              <AlertDialogAction onClick={() => onReject(user.id)}>
                Reject request
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>

        <Button
          variant="accent"
          size="sm"
          loading={isProcessing}
          onClick={() => onApprove(user.id)}
        >
          {!isProcessing && <Check className="h-3.5 w-3.5" />}
          Approve
        </Button>
      </div>
    </div>
  );
}
