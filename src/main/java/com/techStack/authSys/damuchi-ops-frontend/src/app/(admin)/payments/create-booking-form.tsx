"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Skeleton } from "@/components/ui/skeleton";
import {
    Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";

import { paymentApi } from "@/lib/payment-api";
import { tourAdminApi } from "@/lib/tour-admin-api";
import type { AvailabilitySummary } from "@/types/tour-admin";
import type {
    BookingCreatedResponse, PaymentSubmissionResponse, TravelerInfo,
} from "@/types/payment-types";
import type { ApiError } from "@/types/index-types";

interface Props {
    submission: PaymentSubmissionResponse;
    onCreated: (result: BookingCreatedResponse) => void;
    onCancel: () => void;
}

function shortDate(iso: string) {
    return new Date(iso).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" });
}

const emptyTraveler = (fullName = ""): TravelerInfo => ({
    fullName, dateOfBirth: "", passportNumber: "", nationality: "", dietaryNotes: "",
});

export function CreateBookingForm({ submission, onCreated, onCancel }: Props) {
    const partySize = (submission.adultCount ?? 0) + (submission.childCount ?? 0);

    const [slots, setSlots] = useState<AvailabilitySummary[]>([]);
    const [slotsLoading, setSlotsLoading] = useState(true);
    const [availabilityId, setAvailabilityId] = useState("");
    const [pickupLocation, setPickupLocation] = useState("");
    const [pickupTime, setPickupTime] = useState("");
    const [specialInstructions, setSpecialInstructions] = useState("");
    const [travelers, setTravelers] = useState<TravelerInfo[]>(() =>
        Array.from({ length: partySize }, (_, i) => emptyTraveler(i === 0 ? submission.customerName : "")),
    );
    const [isSaving, setIsSaving] = useState(false);

    useEffect(() => {
        let cancelled = false;
        tourAdminApi
            .getUpcomingAvailability(submission.tourId)
            .then((data) => { if (!cancelled) setSlots(data); })
            .catch((err) => toast.error((err as ApiError)?.message || "Couldn't load departure dates."))
            .finally(() => { if (!cancelled) setSlotsLoading(false); });
        return () => { cancelled = true; };
    }, [submission.tourId]);

    // Only departures that can actually take this party.
    const eligible = useMemo(
        () =>
            slots
                .filter((s) => (s.status === "OPEN" || s.status === "LIMITED") && s.availableSeats >= partySize)
                .sort((a, b) => a.departureDate.localeCompare(b.departureDate)),
        [slots, partySize],
    );

    function updateTraveler(index: number, patch: Partial<TravelerInfo>) {
        setTravelers((prev) => prev.map((t, i) => (i === index ? { ...t, ...patch } : t)));
    }

    async function handleSubmit() {
        if (!availabilityId) {
            toast.error("Choose a departure date.");
            return;
        }
        const missing = travelers.findIndex((t) => !t.fullName.trim());
        if (missing !== -1) {
            toast.error(`Enter a full name for traveler ${missing + 1}.`);
            return;
        }

        setIsSaving(true);
        try {
            const result = await paymentApi.adminCreateBooking(submission.id, {
                availabilityId,
                pickupLocation: pickupLocation.trim() || undefined,
                pickupTime: pickupTime || undefined,
                specialInstructions: specialInstructions.trim() || undefined,
                travelers: travelers.map((t) => ({
                    fullName: t.fullName.trim(),
                    dateOfBirth: t.dateOfBirth || undefined,
                    passportNumber: t.passportNumber?.trim() || undefined,
                    nationality: t.nationality?.trim() || undefined,
                    dietaryNotes: t.dietaryNotes?.trim() || undefined,
                })),
            });
            onCreated(result);
        } catch (err) {
            toast.error((err as ApiError)?.message || "Couldn't create booking.");
        } finally {
            setIsSaving(false);
        }
    }

    if (partySize === 0) {
        return <p className="text-sm text-destructive">This quote has no travelers, so a booking can't be created.</p>;
    }

    return (
        <div className="space-y-6">
            <section className="space-y-3">
                <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
                    Departure ({partySize} seat{partySize !== 1 ? "s" : ""} needed)
                </p>

                {slotsLoading ? (
                    <Skeleton className="h-10 w-full rounded-xl" />
                ) : eligible.length === 0 ? (
                    <div className="rounded-xl border border-dashed border-border p-4 text-xs text-muted-foreground">
                        No open departure has {partySize} seats free.{" "}
                        <Link href="/staff/availability" className="font-medium text-primary hover:underline">
                            Manage availability
                        </Link>{" "}
                        to add or reopen a date, then come back.
                    </div>
                ) : (
                    <Select value={availabilityId} onValueChange={setAvailabilityId}>
                        <SelectTrigger className="rounded-xl">
                            <SelectValue placeholder="Select a departure date" />
                        </SelectTrigger>
                        <SelectContent>
                            {eligible.map((s) => (
                                <SelectItem key={s.id} value={s.id}>
                                    {shortDate(s.departureDate)} → {shortDate(s.returnDate)} · {s.availableSeats} seats left
                                </SelectItem>
                            ))}
                        </SelectContent>
                    </Select>
                )}
            </section>

            <section className="space-y-3">
                <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">Pickup details</p>
                <div className="grid grid-cols-2 gap-3">
                    <div className="col-span-2 space-y-1.5 sm:col-span-1">
                        <Label className="text-xs">Pickup location</Label>
                        <Input
                            value={pickupLocation}
                            onChange={(e) => setPickupLocation(e.target.value)}
                            placeholder="e.g. Hotel lobby, Nyali"
                            className="rounded-xl"
                        />
                    </div>
                    <div className="col-span-2 space-y-1.5 sm:col-span-1">
                        <Label className="text-xs">Pickup time</Label>
                        <Input type="time" value={pickupTime} onChange={(e) => setPickupTime(e.target.value)} className="rounded-xl" />
                    </div>
                </div>
                <div className="space-y-1.5">
                    <Label className="text-xs">Special instructions</Label>
                    <Textarea
                        rows={2}
                        value={specialInstructions}
                        onChange={(e) => setSpecialInstructions(e.target.value)}
                        className="resize-none rounded-xl"
                    />
                </div>
            </section>

            <section className="space-y-3">
                <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">Travelers</p>
                {travelers.map((t, i) => (
                    <div key={i} className="space-y-3 rounded-xl border border-border/70 p-3">
                        <p className="text-xs font-semibold text-muted-foreground">
                            Traveler {i + 1}{i === 0 ? " · lead traveler" : ""}
                        </p>
                        <div className="grid grid-cols-2 gap-3">
                            <div className="col-span-2 space-y-1.5">
                                <Label className="text-xs">Full name *</Label>
                                <Input value={t.fullName} onChange={(e) => updateTraveler(i, { fullName: e.target.value })} className="rounded-xl" />
                            </div>
                            <div className="space-y-1.5">
                                <Label className="text-xs">Date of birth</Label>
                                <Input type="date" value={t.dateOfBirth ?? ""} onChange={(e) => updateTraveler(i, { dateOfBirth: e.target.value })} className="rounded-xl" />
                            </div>
                            <div className="space-y-1.5">
                                <Label className="text-xs">Nationality</Label>
                                <Input value={t.nationality ?? ""} onChange={(e) => updateTraveler(i, { nationality: e.target.value })} className="rounded-xl" />
                            </div>
                            <div className="space-y-1.5">
                                <Label className="text-xs">Passport / ID no.</Label>
                                <Input
                                    value={t.passportNumber ?? ""}
                                    onChange={(e) => updateTraveler(i, { passportNumber: e.target.value })}
                                    autoComplete="off"
                                    className="rounded-xl"
                                />
                            </div>
                            <div className="space-y-1.5">
                                <Label className="text-xs">Dietary notes</Label>
                                <Input value={t.dietaryNotes ?? ""} onChange={(e) => updateTraveler(i, { dietaryNotes: e.target.value })} className="rounded-xl" />
                            </div>
                        </div>
                    </div>
                ))}
            </section>

            <div className="grid grid-cols-2 gap-2">
                <Button variant="outline" onClick={onCancel} disabled={isSaving}>
                    Do this later
                </Button>
                <Button onClick={handleSubmit} disabled={isSaving || eligible.length === 0}>
                    {isSaving ? "Creating…" : "Create booking & notify"}
                </Button>
            </div>
            <p className="text-center text-[11px] text-muted-foreground">
                "Do this later" is safe. The payment stays in the "Verified, awaiting booking" tab.
            </p>
        </div>
    );
}