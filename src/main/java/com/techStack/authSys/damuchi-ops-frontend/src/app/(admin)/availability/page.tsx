"use client";

import { useCallback, useEffect, useState } from "react";
import { CalendarDays, Plus, Trash2, AlertTriangle } from "lucide-react";
import { toast } from "sonner";
import { PageHeader } from "@/components/layout/page-header";
import { EmptyState } from "@/components/ui/empty-state";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { tourApi } from "@/lib/tour-api";
import { formatDate } from "@/lib/utils";
import type { ApiError, AvailabilitySlot, TourAdmin } from "@/types";

const STATUS_BADGE: Record<string, "success" | "warning" | "destructive" | "outline" | "secondary"> = {
  OPEN: "success",
  SOLD_OUT: "warning",
  BLOCKED: "destructive",
  UNAVAILABLE: "destructive",
};

export default function StaffAvailabilityPage() {
  const [tours, setTours] = useState<TourAdmin[]>([]);
  const [selectedTour, setSelectedTour] = useState<string>("");
  const [toursLoading, setToursLoading] = useState(true);
  const [toursError, setToursError] = useState<string | null>(null);

  const [slots, setSlots] = useState<AvailabilitySlot[]>([]);
  const [slotsLoading, setSlotsLoading] = useState(false);
  const [slotsError, setSlotsError] = useState<string | null>(null);

  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [confirmingDeleteId, setConfirmingDeleteId] = useState<string | null>(null);

  // New slot form
  const [newDate, setNewDate] = useState("");
  const [newTotal, setNewTotal] = useState(10);
  const [newDeadline, setNewDeadline] = useState("");
  const [isAdding, setIsAdding] = useState(false);

  useEffect(() => {
    // Previously silently swallowed with .catch(console.error) — a failure
    // here left an empty enquire-button.tsx dropdown with zero indication why. Now
    // surfaces the same way every other load-failure does on these pages.
    (async () => {
      setToursLoading(true);
      setToursError(null);
      try {
        const res = await tourApi.adminList({ page: 0, size: 100 });
        setTours(res.content);
        if (res.content.length > 0) setSelectedTour(res.content[0].id);
      } catch (err) {
        const message = (err as ApiError).message || "Couldn't load tours.";
        setToursError(message);
        toast.error(message);
      } finally {
        setToursLoading(false);
      }
    })();
  }, []);

  const loadSlots = useCallback(async () => {
    if (!selectedTour) return;
    setSlotsLoading(true);
    setSlotsError(null);
    setConfirmingDeleteId(null); // stale confirm state shouldn't survive a enquire-button.tsx switch/reload
    try {
      const data = await tourApi.getSlots(selectedTour);
      setSlots(data.sort((a, b) => a.date.localeCompare(b.date)));
    } catch (err) {
      const message = (err as ApiError).message || "Couldn't load availability.";
      setSlotsError(message);
      setSlots([]);
      toast.error(message);
    } finally {
      setSlotsLoading(false);
    }
  }, [selectedTour]);

  useEffect(() => { loadSlots(); }, [loadSlots]);

  async function handleAddSlot(e: React.FormEvent) {
    e.preventDefault();
    if (!newDate || !selectedTour) return;
    setIsAdding(true);
    try {
      const slot = await tourApi.createSlot({
        tourId: selectedTour,
        date: newDate,
        totalSlots: newTotal,
        availableSlots: newTotal,
        bookingDeadline: newDeadline || undefined,
        status: "OPEN",
      });
      setSlots((prev) => [...prev, slot].sort((a, b) => a.date.localeCompare(b.date)));
      setNewDate("");
      setNewTotal(10);
      setNewDeadline("");
      toast.success("Availability slot added.");
    } catch (err) {
      toast.error((err as ApiError).message || "Couldn't add slot.");
    } finally {
      setIsAdding(false);
    }
  }

  async function handleDeleteClick(id: string) {
    if (confirmingDeleteId !== id) {
      setConfirmingDeleteId(id);
      return;
    }
    setDeletingId(id);
    try {
      await tourApi.deleteSlot(id);
      setSlots((prev) => prev.filter((s) => s.id !== id));
      toast.success("Slot removed.");
    } catch (err) {
      toast.error((err as ApiError).message || "Couldn't remove slot.");
    } finally {
      setDeletingId(null);
      setConfirmingDeleteId(null);
    }
  }

  const selectedTourName = tours.find((t) => t.id === selectedTour)?.name ?? "";

  return (
      <div className="space-y-7">
        <PageHeader
            eyebrow="Tour Operations"
            title="Availability"
            subtitle="Set available dates and slot counts for each tour."
        />

        <Card>
          <CardContent className="p-5">
            <Label>Select tour</Label>
            {toursLoading ? (
                <Skeleton className="mt-1.5 h-10 w-full max-w-sm" />
            ) : toursError ? (
                <p className="mt-1.5 text-sm text-destructive">{toursError}</p>
            ) : (
                <Select value={selectedTour} onValueChange={setSelectedTour}>
                  <SelectTrigger className="mt-1.5 max-w-sm">
                    <SelectValue placeholder="Choose a tour" />
                  </SelectTrigger>
                  <SelectContent>
                    {tours.map((t) => (
                        <SelectItem key={t.id} value={t.id}>{t.name}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
            )}
          </CardContent>
        </Card>

        <div className="grid gap-6 lg:grid-cols-3">
          {/* Add slot form */}
          <Card className="h-fit lg:col-span-1">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <Plus className="h-4 w-4 text-accent" />
                Add date
              </CardTitle>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleAddSlot} className="space-y-4">
                <div className="space-y-1.5">
                  <Label>Date</Label>
                  <Input
                      type="date"
                      value={newDate}
                      onChange={(e) => setNewDate(e.target.value)}
                      min={new Date().toISOString().split("T")[0]}
                      required
                  />
                </div>
                <div className="space-y-1.5">
                  <Label>Total slots</Label>
                  <Input
                      type="number"
                      value={newTotal}
                      onChange={(e) => setNewTotal(Number(e.target.value))}
                      min={1}
                      max={200}
                      required
                  />
                </div>
                <div className="space-y-1.5">
                  <Label>
                    Booking deadline <span className="font-normal text-muted-foreground">(optional)</span>
                  </Label>
                  <Input
                      type="datetime-local"
                      value={newDeadline}
                      onChange={(e) => setNewDeadline(e.target.value)}
                  />
                </div>
                <Button
                    type="submit"
                    disabled={isAdding || !newDate || !selectedTour}
                    className="w-full"
                >
                  {isAdding ? "Adding…" : "Add slot"}
                </Button>
              </form>
            </CardContent>
          </Card>

          {/* Slots list */}
          <div className="lg:col-span-2">
            <div className="overflow-hidden rounded-xl border border-border bg-card shadow-sm">
              <div className="flex items-center justify-between border-b border-border px-5 py-4">
                <h2 className="flex items-center gap-2 font-semibold">
                  <CalendarDays className="h-4 w-4 text-accent" />
                  {selectedTourName} — {slots.length} date{slots.length !== 1 ? "s" : ""}
                </h2>
              </div>

              {slotsLoading ? (
                  <div className="divide-y divide-border">
                    {Array.from({ length: 5 }).map((_, i) => (
                        <div key={i} className="flex items-center gap-4 px-5 py-4">
                          <Skeleton className="h-4 w-28" />
                          <Skeleton className="h-4 w-20" />
                          <Skeleton className="ml-auto h-4 w-16" />
                        </div>
                    ))}
                  </div>
              ) : slotsError ? (
                  <div className="p-5">
                    <EmptyState icon={AlertTriangle} title="Couldn't load availability" description={slotsError} />
                  </div>
              ) : slots.length === 0 ? (
                  <div className="p-5">
                    <EmptyState
                        icon={CalendarDays}
                        title="No availability set for this tour"
                        description="Add a date using the form on the left."
                    />
                  </div>
              ) : (
                  <div className="divide-y divide-border">
                    {slots.map((slot) => {
                      const isConfirming = confirmingDeleteId === slot.id;
                      const isDeleting = deletingId === slot.id;
                      return (
                          <div
                              key={slot.id}
                              className="flex items-center gap-4 px-5 py-4 transition-colors hover:bg-muted/50"
                          >
                            <div className="min-w-0 flex-1">
                              <p className="font-medium">
                                {formatDate(slot.date, { weekday: "short", month: "short", day: "numeric", year: "numeric" })}
                              </p>
                              {slot.bookingDeadline && (
                                  <p className="mt-0.5 text-xs text-muted-foreground">
                                    Deadline: {formatDate(slot.bookingDeadline, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}
                                  </p>
                              )}
                            </div>
                            <div className="shrink-0 text-right text-sm">
                              <p className="font-mono">
                                <span className="font-semibold text-accent">{slot.availableSlots}</span>
                                <span className="text-muted-foreground"> / {slot.totalSlots}</span>
                              </p>
                              <p className="text-xs text-muted-foreground">available</p>
                            </div>
                            <Badge variant={STATUS_BADGE[slot.status] ?? "outline"} className="shrink-0 rounded-full text-[10px] font-medium">
                              {slot.status.replace("_", " ")}
                            </Badge>
                            <Button
                                variant={isConfirming ? "destructive" : "ghost"}
                                size="sm"
                                onClick={() => handleDeleteClick(slot.id)}
                                disabled={isDeleting}
                                className="shrink-0"
                                title={isConfirming ? "Click again to confirm" : "Remove slot"}
                            >
                              <Trash2 className="h-3.5 w-3.5" />
                              {isConfirming && (isDeleting ? "Removing…" : "Confirm")}
                            </Button>
                          </div>
                      );
                    })}
                  </div>
              )}
            </div>
          </div>
        </div>
      </div>
  );
}