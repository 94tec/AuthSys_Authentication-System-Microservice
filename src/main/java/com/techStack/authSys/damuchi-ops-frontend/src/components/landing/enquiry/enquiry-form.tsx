// components/enquiry/enquiry-form.tsx
"use client";

import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { toast } from "sonner";
import {
    CalendarDays,
    Check,
    ChevronDown,
    CircleUserRound,
    Mail,
    MessageCircle,
    Phone,
    ShieldCheck,
    UsersRound,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
    Form,
    FormControl,
    FormField,
    FormItem,
    FormLabel,
    FormMessage,
} from "@/components/ui/form";

import {
    enquirySchema,
    type EnquiryFormValues,
    PREFERRED_CONTACT_OPTIONS,
    PREFERRED_CONTACT_LABELS,
} from "@/lib/validations/enquiry";

import { enquiryApi } from "@/lib/enquiry-api";

interface EnquiryFormProps {
    /** Required — enquiry endpoint requires a tour. */
    tourId: string;

    /** Display-only tour context. */
    tourName?: string;

    availabilityId?: string;

    /** Where the enquiry originated. */
    source?: string;

    onSuccess?: () => void;
}

const inputClassName =
    "h-11 rounded-xl border-border/70 bg-background/70 px-3.5 text-sm shadow-sm transition-all placeholder:text-muted-foreground/60 focus:border-coral focus:ring-2 focus:ring-coral/15";

const selectClassName =
    "h-11 w-full appearance-none rounded-xl border border-border/70 bg-background/70 px-3.5 pr-10 text-sm shadow-sm outline-none transition-all focus:border-coral focus:ring-2 focus:ring-coral/15";

const textareaClassName =
    "min-h-[104px] w-full resize-y rounded-xl border border-border/70 bg-background/70 px-3.5 py-3 text-sm shadow-sm outline-none transition-all placeholder:text-muted-foreground/60 focus:border-coral focus:ring-2 focus:ring-coral/15";

export function EnquiryForm({
    tourId,
    tourName,
    availabilityId,
    source,
    onSuccess,
}: EnquiryFormProps) {
    const form = useForm<EnquiryFormValues>({
        resolver: zodResolver(enquirySchema),
        defaultValues: {
            fullName: "",
            email: "",
            phone: "",
            tourId,
            availabilityId,
            flexibleDates: false,
            consent: false,
            source,
        },
    });

    async function onSubmit(values: EnquiryFormValues) {
        try {
            const { tourId, availabilityId, ...payload } = values;
            await enquiryApi.createEnquiry(tourId, payload);

            toast.success("Enquiry sent — we'll reply within 2 hours.");

            form.reset({
                ...values,
                fullName: "",
                email: "",
                phone: "",
                requirements: "",
                consent: false,
            });

            onSuccess?.();
        } catch {
            toast.error("Couldn't send your enquiry. Please try again.");
        }
    }

    return (
        <div className="w-full">
            {/* Tour context */}
            {tourName && (
                <div className="mb-5 rounded-2xl border border-coral/15 bg-coral/[0.06] p-3.5 shadow-sm backdrop-blur-sm">
                    <div className="flex items-center gap-3">
                        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-coral/10 text-coral">
                            <MessageCircle className="h-4 w-4" />
                        </div>

                        <div className="min-w-0">
                            <p className="text-[10px] font-semibold uppercase tracking-[0.12em] text-coral/80">
                                Enquiring about
                            </p>
                            <p className="mt-0.5 truncate text-sm font-semibold text-foreground">
                                {tourName}
                            </p>
                        </div>

                        <div className="ml-auto flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-coral/10 text-coral">
                            <Check className="h-3.5 w-3.5" />
                        </div>
                    </div>
                </div>
            )}

            <Form {...form}>
                <form
                    onSubmit={form.handleSubmit(onSubmit)}
                    className="space-y-6"
                >
                    {/* ───────────────── Contact ───────────────── */}
                    <section>
                        <div className="mb-3.5 flex items-center gap-2">
                            <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-muted/70">
                                <CircleUserRound className="h-3.5 w-3.5 text-muted-foreground" />
                            </div>

                            <div>
                                <h3 className="text-sm font-semibold">
                                    Your details
                                </h3>
                                <p className="text-[11px] text-muted-foreground">
                                    How should we get in touch?
                                </p>
                            </div>
                        </div>

                        <div className="space-y-3">
                            {/* Name */}
                            <FormField
                                control={form.control}
                                name="fullName"
                                render={({ field }) => (
                                    <FormItem>
                                        <FormLabel className="text-xs font-medium">
                                            Full name
                                        </FormLabel>

                                        <FormControl>
                                            <div className="relative">
                                                <CircleUserRound className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground/50" />

                                                <Input
                                                    {...field}
                                                    placeholder="Jane Doe"
                                                    autoComplete="name"
                                                    className={`${inputClassName} pl-10`}
                                                />
                                            </div>
                                        </FormControl>

                                        <FormMessage className="text-xs" />
                                    </FormItem>
                                )}
                            />

                            {/* Email */}
                            <FormField
                                control={form.control}
                                name="email"
                                render={({ field }) => (
                                    <FormItem>
                                        <FormLabel className="text-xs font-medium">
                                            Email address
                                        </FormLabel>

                                        <FormControl>
                                            <div className="relative">
                                                <Mail className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground/50" />

                                                <Input
                                                    {...field}
                                                    type="email"
                                                    placeholder="you@example.com"
                                                    autoComplete="email"
                                                    className={`${inputClassName} pl-10`}
                                                />
                                            </div>
                                        </FormControl>

                                        <FormMessage className="text-xs" />
                                    </FormItem>
                                )}
                            />

                            {/* Phone + contact preference */}
                            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                                <FormField
                                    control={form.control}
                                    name="phone"
                                    render={({ field }) => (
                                        <FormItem>
                                            <FormLabel className="text-xs font-medium">
                                                Phone
                                                <span className="ml-1 font-normal text-muted-foreground">
                                                    optional
                                                </span>
                                            </FormLabel>

                                            <FormControl>
                                                <div className="relative">
                                                    <Phone className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground/50" />

                                                    <Input
                                                        {...field}
                                                        type="tel"
                                                        placeholder="+254 7xx xxx xxx"
                                                        autoComplete="tel"
                                                        className={`${inputClassName} pl-10`}
                                                    />
                                                </div>
                                            </FormControl>

                                            <FormMessage className="text-xs" />
                                        </FormItem>
                                    )}
                                />

                                <FormField
                                    control={form.control}
                                    name="preferredContact"
                                    render={({ field }) => (
                                        <FormItem>
                                            <FormLabel className="text-xs font-medium">
                                                Contact via
                                            </FormLabel>

                                            <FormControl>
                                                <div className="relative">
                                                    <select
                                                        {...field}
                                                        className={selectClassName}
                                                    >
                                                        <option value="">
                                                            No preference
                                                        </option>

                                                        {PREFERRED_CONTACT_OPTIONS.map(
                                                            (option) => (
                                                                <option
                                                                    key={option}
                                                                    value={option}
                                                                >
                                                                    {
                                                                        PREFERRED_CONTACT_LABELS[
                                                                            option
                                                                        ]
                                                                    }
                                                                </option>
                                                            ),
                                                        )}
                                                    </select>

                                                    <ChevronDown className="pointer-events-none absolute right-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground/60" />
                                                </div>
                                            </FormControl>

                                            <FormMessage className="text-xs" />
                                        </FormItem>
                                    )}
                                />
                            </div>
                        </div>
                    </section>

                    {/* ───────────────── Trip details ───────────────── */}
                    <section>
                        <div className="mb-3.5 flex items-center gap-2">
                            <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-muted/70">
                                <CalendarDays className="h-3.5 w-3.5 text-muted-foreground" />
                            </div>

                            <div>
                                <h3 className="text-sm font-semibold">
                                    Trip details
                                </h3>
                                <p className="text-[11px] text-muted-foreground">
                                    Help us understand your plans
                                </p>
                            </div>
                        </div>

                        <div className="space-y-3">
                            {/* Group size */}
                            <div className="grid grid-cols-2 gap-3">
                                <FormField
                                    control={form.control}
                                    name="groupSizeAdults"
                                    render={({ field }) => (
                                        <FormItem>
                                            <FormLabel className="text-xs font-medium">
                                                Adults
                                            </FormLabel>

                                            <FormControl>
                                                <div className="relative">
                                                    <UsersRound className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground/50" />

                                                    <Input
                                                        {...field}
                                                        type="number"
                                                        min={1}
                                                        inputMode="numeric"
                                                        placeholder="2"
                                                        className={`${inputClassName} pl-10`}
                                                        onChange={(event) =>
                                                            field.onChange(
                                                                event.target
                                                                    .value
                                                                    ? Number(
                                                                          event
                                                                              .target
                                                                              .value,
                                                                      )
                                                                    : undefined,
                                                            )
                                                        }
                                                    />
                                                </div>
                                            </FormControl>

                                            <FormMessage className="text-xs" />
                                        </FormItem>
                                    )}
                                />

                                <FormField
                                    control={form.control}
                                    name="groupSizeChildren"
                                    render={({ field }) => (
                                        <FormItem>
                                            <FormLabel className="text-xs font-medium">
                                                Children
                                                <span className="ml-1 font-normal text-muted-foreground">
                                                    optional
                                                </span>
                                            </FormLabel>

                                            <FormControl>
                                                <div className="relative">
                                                    <UsersRound className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground/50" />

                                                    <Input
                                                        {...field}
                                                        type="number"
                                                        min={0}
                                                        inputMode="numeric"
                                                        placeholder="0"
                                                        className={`${inputClassName} pl-10`}
                                                        onChange={(event) =>
                                                            field.onChange(
                                                                event.target
                                                                    .value
                                                                    ? Number(
                                                                          event
                                                                              .target
                                                                              .value,
                                                                      )
                                                                    : undefined,
                                                            )
                                                        }
                                                    />
                                                </div>
                                            </FormControl>

                                            <FormMessage className="text-xs" />
                                        </FormItem>
                                    )}
                                />
                            </div>

                            {/* Preferred date */}
                            <FormField
                                control={form.control}
                                name="preferredDate"
                                render={({ field }) => (
                                    <FormItem>
                                        <FormLabel className="text-xs font-medium">
                                            Preferred date
                                            <span className="ml-1 font-normal text-muted-foreground">
                                                optional
                                            </span>
                                        </FormLabel>

                                        <FormControl>
                                            <div className="relative">
                                                <CalendarDays className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground/50" />

                                                <Input
                                                    {...field}
                                                    type="date"
                                                    className={`${inputClassName} pl-10`}
                                                />
                                            </div>
                                        </FormControl>

                                        <FormMessage className="text-xs" />
                                    </FormItem>
                                )}
                            />

                            {/* Flexible dates */}
                            <FormField
                                control={form.control}
                                name="flexibleDates"
                                render={({ field }) => (
                                    <FormItem className="space-y-0">
                                        <FormControl>
                                            <label
                                                htmlFor="flexible-dates"
                                                className="group flex cursor-pointer items-start gap-3 rounded-xl border border-border/60 bg-muted/20 p-3 transition-colors hover:bg-muted/40"
                                            >
                                                <input
                                                    id="flexible-dates"
                                                    type="checkbox"
                                                    checked={field.value}
                                                    onChange={(event) =>
                                                        field.onChange(
                                                            event.target.checked,
                                                        )
                                                    }
                                                    className="mt-0.5 h-4 w-4 shrink-0 rounded border-border text-coral accent-coral focus:ring-2 focus:ring-coral/20"
                                                />

                                                <span>
                                                    <span className="block text-sm font-medium">
                                                        My dates are flexible
                                                    </span>

                                                    <span className="mt-0.5 block text-xs leading-relaxed text-muted-foreground">
                                                        We can suggest dates with
                                                        better availability.
                                                    </span>
                                                </span>
                                            </label>
                                        </FormControl>

                                        <FormMessage className="mt-1 text-xs" />
                                    </FormItem>
                                )}
                            />
                        </div>
                    </section>

                    {/* ───────────────── Preferences ───────────────── */}
                    <section>
                        <div className="mb-3.5">
                            <h3 className="text-sm font-semibold">
                                Preferences
                            </h3>
                            <p className="mt-0.5 text-[11px] text-muted-foreground">
                                Optional details help us tailor the trip.
                            </p>
                        </div>

                        <div className="space-y-3">
                            {/* Budget */}
                            <FormField
                                control={form.control}
                                name="budgetRange"
                                render={({ field }) => (
                                    <FormItem>
                                        <FormLabel className="text-xs font-medium">
                                            Budget range
                                            <span className="ml-1 font-normal text-muted-foreground">
                                                optional
                                            </span>
                                        </FormLabel>

                                        <FormControl>
                                            <Input
                                                {...field}
                                                placeholder="$1,500–$2,500 per person"
                                                className={inputClassName}
                                            />
                                        </FormControl>

                                        <FormMessage className="text-xs" />
                                    </FormItem>
                                )}
                            />

                            {/* Requirements */}
                            <FormField
                                control={form.control}
                                name="requirements"
                                render={({ field }) => (
                                    <FormItem>
                                        <FormLabel className="text-xs font-medium">
                                            Anything else we should know?
                                            <span className="ml-1 font-normal text-muted-foreground">
                                                optional
                                            </span>
                                        </FormLabel>

                                        <FormControl>
                                            <textarea
                                                {...field}
                                                rows={4}
                                                className={textareaClassName}
                                                placeholder="Dietary needs, accessibility, special occasions, interests..."
                                            />
                                        </FormControl>

                                        <FormMessage className="text-xs" />
                                    </FormItem>
                                )}
                            />
                        </div>
                    </section>

                    {/* ───────────────── Consent ───────────────── */}
                    <FormField
                        control={form.control}
                        name="consent"
                        render={({ field }) => (
                            <FormItem className="space-y-0">
                                <FormControl>
                                    <label
                                        htmlFor="enquiry-consent"
                                        className="flex cursor-pointer items-start gap-3 rounded-xl border border-border/60 bg-muted/20 p-3.5 transition-colors hover:bg-muted/40"
                                    >
                                        <input
                                            id="enquiry-consent"
                                            type="checkbox"
                                            checked={field.value}
                                            onChange={(event) =>
                                                field.onChange(
                                                    event.target.checked,
                                                )
                                            }
                                            className="mt-0.5 h-4 w-4 shrink-0 rounded border-border text-coral accent-coral focus:ring-2 focus:ring-coral/20"
                                        />

                                        <span className="text-xs leading-relaxed text-muted-foreground">
                                            I agree to be contacted about this
                                            enquiry and understand my details
                                            will be handled according to the
                                            privacy policy.
                                        </span>
                                    </label>
                                </FormControl>

                                <FormMessage className="mt-1 text-xs" />
                            </FormItem>
                        )}
                    />

                    {/* ───────────────── Submit ───────────────── */}
                    <div className="space-y-3 pt-1">
                        <Button
                            type="submit"
                            variant="accent"
                            size="lg"
                            className="h-12 w-full rounded-xl text-sm font-semibold shadow-lg shadow-coral/10 transition-all hover:shadow-xl hover:shadow-coral/15"
                            loading={form.formState.isSubmitting}
                        >
                            Send enquiry
                        </Button>

                        <div className="flex items-center justify-center gap-1.5 text-center text-[11px] text-muted-foreground/70">
                            <ShieldCheck className="h-3.5 w-3.5 shrink-0" />
                            <span>
                                Your details are encrypted and never shared
                                with third parties.
                            </span>
                        </div>
                    </div>
                </form>
            </Form>
        </div>
    );
}
