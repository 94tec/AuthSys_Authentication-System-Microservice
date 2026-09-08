"use client";

import { useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import {
  AlertTriangle,
  ArrowLeft,
  Banknote,
  Check,
  CheckCircle2,
  ChevronRight,
  Clock,
  Compass,
  GripVertical,
  ImagePlus,
  Info,
  ListChecks,
  Loader2,
  Map,
  Mountain,
  Plus,
  ShieldCheck,
  Sparkles,
  Star,
  Users,
  Video,
  X,
} from "lucide-react";
import { toast } from "sonner";

import { PageHeader } from "@/components/layout/page-header";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

import { tourAdminApi } from "@/lib/tour-admin-api";
import { formatCurrency } from "@/lib/utils";

import type {
  CreateTourPayload,
  TourCategory,
  TourCurrency,
  TourDifficulty,
  TourPriceType,
} from "@/types/tour-admin";

import type { ApiError } from "@/types/index-types";

/* -------------------------------------------------------------------------- */
/* Options                                                                    */
/* -------------------------------------------------------------------------- */

const CATEGORIES: { value: TourCategory; label: string }[] = [
  { value: "WILDLIFE", label: "Wildlife" },
  { value: "MOUNTAIN", label: "Mountain" },
  { value: "BEACH", label: "Beach" },
  { value: "CULTURAL", label: "Cultural" },
  { value: "ADVENTURE", label: "Adventure" },
  { value: "PHOTOGRAPHY", label: "Photography" },
  { value: "FAMILY", label: "Family" },
  { value: "LUXURY", label: "Luxury" },
];

const CATEGORY_STYLES: Partial<Record<TourCategory, string>> = {
  WILDLIFE: "bg-emerald-500/10 text-emerald-700 dark:text-emerald-400",
  MOUNTAIN: "bg-stone-500/10 text-stone-700 dark:text-stone-300",
  BEACH: "bg-sky-500/10 text-sky-700 dark:text-sky-400",
  CULTURAL: "bg-violet-500/10 text-violet-700 dark:text-violet-400",
  ADVENTURE: "bg-orange-500/10 text-orange-700 dark:text-orange-400",
  PHOTOGRAPHY: "bg-indigo-500/10 text-indigo-700 dark:text-indigo-400",
  FAMILY: "bg-pink-500/10 text-pink-700 dark:text-pink-400",
  LUXURY: "bg-amber-500/10 text-amber-700 dark:text-amber-400",
};

const DIFFICULTIES: {
  value: TourDifficulty;
  label: string;
}[] = [
  {
    value: "EASY",
    label: "Easy — gentle pace, all fitness levels",
  },
  {
    value: "MODERATE",
    label: "Moderate — some walking or long drives",
  },
  {
    value: "CHALLENGING",
    label: "Challenging — physically demanding",
  },
  {
    value: "STRENUOUS",
    label: "Strenuous — high altitude or endurance",
  },
];

const CURRENCIES: {
  value: TourCurrency;
  label: string;
}[] = [
  {
    value: "KES",
    label: "KES — Kenyan Shilling",
  },
  {
    value: "USD",
    label: "USD — US Dollar",
  },
  {
    value: "EUR",
    label: "EUR — Euro",
  },
  {
    value: "GBP",
    label: "GBP — British Pound",
  },
];

const PRICE_TYPES: {
  value: TourPriceType;
  label: string;
}[] = [
  {
    value: "PER_PERSON",
    label: "Per person",
  },
  {
    value: "PER_GROUP",
    label: "Per group",
  },
  {
    value: "PER_ROOM",
    label: "Per room",
  },
];

const LIMITS = {
  name: 150,
  shortDescription: 500,
  description: 10000,
  destination: 150,
  country: 100,
  region: 150,
  meetingPoint: 300,
  importantInformation: 5000,
} as const;

/* -------------------------------------------------------------------------- */
/* Form state                                                                 */
/* -------------------------------------------------------------------------- */

interface FormState {
  name: string;
  shortDescription: string;
  description: string;

  category: TourCategory | "";

  destination: string;
  country: string;
  region: string;
  meetingPoint: string;

  durationDays: string;
  durationNights: string;
  difficulty: TourDifficulty | "";
  minimumAge: string;
  maxGroupSize: string;
  bestSeason: string;

  price: string;
  currency: TourCurrency | "";
  priceType: TourPriceType | "";
  depositPercentage: string;

  highlights: string[];
  itinerary: string[];
  inclusions: string[];
  exclusions: string[];
  requirements: string[];

  importantInformation: string;

  coverImage: string;
  galleryImages: string[];
  videoUrl: string;

  active: boolean;
  featured: boolean;
}

const EMPTY_FORM: FormState = {
  name: "",
  shortDescription: "",
  description: "",

  category: "",

  destination: "",
  country: "Kenya",
  region: "",
  meetingPoint: "",

  durationDays: "",
  durationNights: "",
  difficulty: "",
  minimumAge: "",
  maxGroupSize: "",
  bestSeason: "",

  price: "",
  currency: "KES",
  priceType: "PER_PERSON",
  depositPercentage: "20",

  highlights: [],
  itinerary: [],
  inclusions: [],
  exclusions: [],
  requirements: [],

  importantInformation: "",

  coverImage: "",
  galleryImages: [],
  videoUrl: "",

  active: true,
  featured: false,
};

/* -------------------------------------------------------------------------- */
/* Reusable UI                                                                */
/* -------------------------------------------------------------------------- */

function FieldLabel({
                      children,
                      required,
                      count,
                      limit,
                    }: {
  children: React.ReactNode;
  required?: boolean;
  count?: number;
  limit?: number;
}) {
  return (
      <div className="flex items-center justify-between gap-3">
        <Label className="text-xs font-medium text-muted-foreground">
          {children}
          {required && (
              <span className="ml-1 text-destructive" aria-hidden="true">
            *
          </span>
          )}
        </Label>

        {typeof count === "number" && typeof limit === "number" && (
            <span
                className={`text-[10px] tabular-nums ${
                    count > limit
                        ? "text-destructive"
                        : "text-muted-foreground/60"
                }`}
            >
          {count}/{limit}
        </span>
        )}
      </div>
  );
}

function Field({
                 label,
                 required,
                 count,
                 limit,
                 children,
               }: {
  label: React.ReactNode;
  required?: boolean;
  count?: number;
  limit?: number;
  children: React.ReactNode;
}) {
  return (
      <div className="space-y-1.5">
        <FieldLabel
            required={required}
            count={count}
            limit={limit}
        >
          {label}
        </FieldLabel>

        {children}
      </div>
  );
}

function Section({
                   icon: Icon,
                   title,
                   description,
                   children,
                   status,
                 }: {
  icon: React.ElementType;
  title: string;
  description: string;
  children: React.ReactNode;
  status?: "complete" | "incomplete";
}) {
  return (
      <section
          className="scroll-mt-24 rounded-2xl border bg-card/80 shadow-sm"
      >
        <div className="flex items-start justify-between gap-4 border-b px-5 py-4 sm:px-6">
          <div className="flex min-w-0 items-start gap-3">
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-primary/10 text-primary">
              <Icon className="h-4 w-4" />
            </div>

            <div className="min-w-0">
              <h2 className="font-display text-sm font-semibold tracking-tight sm:text-base">
                {title}
              </h2>

              <p className="mt-0.5 text-xs leading-relaxed text-muted-foreground">
                {description}
              </p>
            </div>
          </div>

          {status && (
              <div className="shrink-0">
                {status === "complete" ? (
                    <Badge
                        variant="outline"
                        className="gap-1 rounded-full border-emerald-500/20 bg-emerald-500/10 text-[10px] text-emerald-700 dark:text-emerald-400"
                    >
                      <CheckCircle2 className="h-3 w-3" />
                      Complete
                    </Badge>
                ) : (
                    <Badge
                        variant="outline"
                        className="rounded-full border-none bg-muted text-[10px] text-muted-foreground"
                    >
                      Required
                    </Badge>
                )}
              </div>
          )}
        </div>

        <div className="p-5 sm:p-6">{children}</div>
      </section>
  );
}

/* -------------------------------------------------------------------------- */
/* Tag list                                                                   */
/* -------------------------------------------------------------------------- */

function TagListField({
                        values,
                        onChange,
                        placeholder,
                        emptyHint,
                      }: {
  values: string[];
  onChange: (next: string[]) => void;
  placeholder: string;
  emptyHint: string;
}) {
  const [draft, setDraft] = useState("");

  function commit() {
    const trimmed = draft.trim();

    if (!trimmed) return;

    if (
        values.some(
            (value) => value.toLowerCase() === trimmed.toLowerCase()
        )
    ) {
      toast.info("That item has already been added.");
      return;
    }

    onChange([...values, trimmed]);
    setDraft("");
  }

  function remove(index: number) {
    onChange(values.filter((_, i) => i !== index));
  }

  return (
      <div className="space-y-3">
        <div className="flex gap-2">
          <Input
              value={draft}
              onChange={(event) => setDraft(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") {
                  event.preventDefault();
                  commit();
                }
              }}
              placeholder={placeholder}
              className="h-10 border-none bg-muted/50 shadow-none"
          />

          <Button
              type="button"
              variant="outline"
              size="icon"
              onClick={commit}
              className="h-10 w-10 shrink-0"
              aria-label="Add item"
          >
            <Plus className="h-4 w-4" />
          </Button>
        </div>

        {values.length === 0 ? (
            <div className="flex items-center gap-2 rounded-xl border border-dashed px-3 py-2.5 text-xs text-muted-foreground">
              <Info className="h-3.5 w-3.5 shrink-0" />
              {emptyHint}
            </div>
        ) : (
            <div className="flex flex-wrap gap-2">
              {values.map((value, index) => (
                  <Badge
                      key={`${value}-${index}`}
                      variant="outline"
                      className="gap-1.5 rounded-full border-none bg-muted/70 py-1.5 pl-3 pr-1.5 text-xs font-normal"
                  >
                    {value}

                    <button
                        type="button"
                        onClick={() => remove(index)}
                        className="rounded-full p-0.5 text-muted-foreground/60 transition-colors hover:bg-background hover:text-foreground"
                        aria-label={`Remove ${value}`}
                    >
                      <X className="h-3 w-3" />
                    </button>
                  </Badge>
              ))}
            </div>
        )}
      </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Itinerary                                                                  */
/* -------------------------------------------------------------------------- */

function ItineraryField({
                          values,
                          onChange,
                        }: {
  values: string[];
  onChange: (next: string[]) => void;
}) {
  const [draft, setDraft] = useState("");

  function commit() {
    const trimmed = draft.trim();

    if (!trimmed) return;

    onChange([...values, trimmed]);
    setDraft("");
  }

  return (
      <div className="space-y-3">
        <div className="flex gap-2">
          <Input
              value={draft}
              onChange={(event) => setDraft(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") {
                  event.preventDefault();
                  commit();
                }
              }}
              placeholder={`Day ${values.length + 1} — what happens?`}
              className="h-10 border-none bg-muted/50 shadow-none"
          />

          <Button
              type="button"
              variant="outline"
              size="icon"
              onClick={commit}
              className="h-10 w-10 shrink-0"
              aria-label="Add itinerary day"
          >
            <Plus className="h-4 w-4" />
          </Button>
        </div>

        {values.length === 0 ? (
            <div className="rounded-xl border border-dashed px-3 py-3 text-xs text-muted-foreground">
              Add one line per day. Day numbers are assigned automatically.
            </div>
        ) : (
            <div className="space-y-2">
              {values.map((value, index) => (
                  <div
                      key={`${value}-${index}`}
                      className="group flex items-center gap-2 rounded-xl bg-muted/40 px-3 py-2.5"
                  >
                    <GripVertical className="h-4 w-4 shrink-0 text-muted-foreground/30" />

                    <span className="w-12 shrink-0 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
                Day {index + 1}
              </span>

                    <span className="min-w-0 flex-1 text-sm">
                {value}
              </span>

                    <button
                        type="button"
                        onClick={() =>
                            onChange(values.filter((_, i) => i !== index))
                        }
                        className="rounded-full p-1 text-muted-foreground/40 opacity-70 transition hover:bg-background hover:text-foreground group-hover:opacity-100"
                        aria-label={`Remove day ${index + 1}`}
                    >
                      <X className="h-3.5 w-3.5" />
                    </button>
                  </div>
              ))}
            </div>
        )}
      </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Sidebar                                                                    */
/* -------------------------------------------------------------------------- */

function PreviewStat({
                       icon: Icon,
                       value,
                     }: {
  icon: React.ElementType;
  value: string;
}) {
  return (
      <span className="inline-flex items-center gap-1 text-[11px] text-muted-foreground">
      <Icon className="h-3.5 w-3.5" />
        {value}
    </span>
  );
}

/* -------------------------------------------------------------------------- */
/* Page                                                                       */
/* -------------------------------------------------------------------------- */

export default function NewTourPage() {
  const router = useRouter();

  const [form, setForm] = useState<FormState>(EMPTY_FORM);
  const [isSubmitting, setIsSubmitting] = useState(false);

  function set<K extends keyof FormState>(
      key: K,
      value: FormState[K]
  ) {
    setForm((previous) => ({
      ...previous,
      [key]: value,
    }));
  }

  const sectionStatus = useMemo(
      () => ({
        identity: Boolean(
            form.name.trim() &&
            form.shortDescription.trim() &&
            form.description.trim() &&
            form.category
        ),

        destination: Boolean(
            form.destination.trim() && form.country.trim()
        ),

        trip: Boolean(
            form.durationDays &&
            Number(form.durationDays) >= 1 &&
            form.durationNights !== "" &&
            Number(form.durationNights) >= 0 &&
            form.difficulty
        ),

        pricing: Boolean(
            form.price !== "" &&
            Number(form.price) >= 0 &&
            form.currency &&
            form.priceType
        ),

        content: Boolean(
            form.highlights.length ||
            form.itinerary.length ||
            form.inclusions.length ||
            form.exclusions.length
        ),

        media: Boolean(form.coverImage.trim()),
      }),
      [form]
  );

  const requiredSections = [
    "identity",
    "destination",
    "trip",
    "pricing",
    "media",
  ] as const;

  const completedRequiredSections = requiredSections.filter(
      (key) => sectionStatus[key]
  ).length;

  const progress = Math.round(
      (completedRequiredSections / requiredSections.length) * 100
  );

  const previewPrice =
      form.price &&
      form.currency &&
      Number.isFinite(Number(form.price))
          ? formatCurrency(Number(form.price), form.currency)
          : null;

  function validate(): string | null {
    if (!form.name.trim()) {
      return "Tour name is required.";
    }

    if (form.name.length > LIMITS.name) {
      return `Tour name cannot exceed ${LIMITS.name} characters.`;
    }

    if (!form.shortDescription.trim()) {
      return "Short description is required.";
    }

    if (form.shortDescription.length > LIMITS.shortDescription) {
      return `Short description cannot exceed ${LIMITS.shortDescription} characters.`;
    }

    if (!form.description.trim()) {
      return "Full description is required.";
    }

    if (form.description.length > LIMITS.description) {
      return `Full description cannot exceed ${LIMITS.description} characters.`;
    }

    if (!form.category) {
      return "Pick a tour category.";
    }

    if (!form.destination.trim()) {
      return "Destination is required.";
    }

    if (!form.country.trim()) {
      return "Country is required.";
    }

    if (
        !form.durationDays ||
        Number(form.durationDays) < 1
    ) {
      return "Duration in days must be at least 1.";
    }

    if (
        form.durationNights === "" ||
        Number(form.durationNights) < 0
    ) {
      return "Duration in nights is required.";
    }

    if (!form.difficulty) {
      return "Pick a difficulty level.";
    }

    if (form.minimumAge && Number(form.minimumAge) < 1) {
      return "Minimum age must be at least 1.";
    }

    if (form.maxGroupSize && Number(form.maxGroupSize) < 1) {
      return "Maximum group size must be at least 1.";
    }

    if (
        form.price === "" ||
        Number(form.price) < 0
    ) {
      return "A valid price is required.";
    }

    if (!form.currency) {
      return "Pick a currency.";
    }

    if (!form.priceType) {
      return "Pick how the price is charged.";
    }

    if (
        form.depositPercentage &&
        (Number(form.depositPercentage) < 0 ||
            Number(form.depositPercentage) > 100)
    ) {
      return "Deposit percentage must be between 0 and 100.";
    }

    if (!form.coverImage.trim()) {
      return "A cover image is required.";
    }

    return null;
  }

  async function handleSubmit(
      event: React.FormEvent<HTMLFormElement>
  ) {
    event.preventDefault();

    const validationError = validate();

    if (validationError) {
      toast.error(validationError);
      return;
    }

    setIsSubmitting(true);

    try {
      const payload: CreateTourPayload = {
        name: form.name.trim(),
        shortDescription: form.shortDescription.trim(),
        description: form.description.trim(),

        category: form.category as TourCategory,

        destination: form.destination.trim(),
        country: form.country.trim(),
        region: form.region.trim() || undefined,
        meetingPoint: form.meetingPoint.trim() || undefined,

        durationDays: Number(form.durationDays),
        durationNights: Number(form.durationNights),

        difficulty: form.difficulty as TourDifficulty,

        minimumAge: form.minimumAge
            ? Number(form.minimumAge)
            : undefined,

        maxGroupSize: form.maxGroupSize
            ? Number(form.maxGroupSize)
            : undefined,

        bestSeason: form.bestSeason.trim() || undefined,

        price: Number(form.price),

        currency: form.currency as TourCurrency,

        priceType: form.priceType as TourPriceType,

        depositPercentage: form.depositPercentage
            ? Number(form.depositPercentage)
            : undefined,

        highlights: form.highlights,
        itinerary: form.itinerary,
        inclusions: form.inclusions,
        exclusions: form.exclusions,
        requirements: form.requirements,

        importantInformation:
            form.importantInformation.trim() || undefined,

        coverImage: form.coverImage.trim(),

        galleryImages: form.galleryImages,

        videoUrl: form.videoUrl.trim() || undefined,

        active: form.active,
        featured: form.featured,
      };

      const created = await tourAdminApi.createTour(payload);

      toast.success(`"${form.name.trim()}" created successfully.`);

      router.push(`/tours/${created.id}`);
    } catch (error) {
      const apiError = error as ApiError;

      toast.error(
          apiError?.message || "Couldn't create the tour."
      );
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
      <form
          onSubmit={handleSubmit}
          className="min-h-full space-y-6 pb-16"
      >
        {/* ------------------------------------------------------------------ */}
        {/* Header                                                             */}
        {/* ------------------------------------------------------------------ */}

        <PageHeader
            eyebrow="Tour Operations"
            title="New tour"
            subtitle="Create a polished itinerary and publish it to the catalogue."
            action={
              <div className="flex items-center gap-2">
                <Button
                    asChild
                    type="button"
                    variant="outline"
                    size="sm"
                >
                  <Link href="/tours">
                    <ArrowLeft className="h-3.5 w-3.5" />
                    <span className="hidden sm:inline">
                  Catalogue
                </span>
                    <span className="sm:hidden">Back</span>
                  </Link>
                </Button>

                <Button
                    type="submit"
                    size="sm"
                    disabled={isSubmitting}
                    className="gap-1.5"
                >
                  {isSubmitting ? (
                      <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                      <Sparkles className="h-3.5 w-3.5" />
                  )}

                  {isSubmitting
                      ? "Creating..."
                      : "Create tour"}
                </Button>
              </div>
            }
        />

        {/* ------------------------------------------------------------------ */}
        {/* Command summary                                                     */}
        {/* ------------------------------------------------------------------ */}

        <div className="grid gap-3 sm:grid-cols-3">
          <Card className="rounded-2xl border bg-card/70 shadow-sm">
            <CardContent className="flex items-center gap-3 p-4">
              <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-primary/10 text-primary">
                <CheckCircle2 className="h-4 w-4" />
              </div>

              <div className="min-w-0">
                <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                  Setup
                </p>
                <p className="text-sm font-semibold">
                  {completedRequiredSections}/
                  {requiredSections.length} required
                </p>
              </div>
            </CardContent>
          </Card>

          <Card className="rounded-2xl border bg-card/70 shadow-sm">
            <CardContent className="flex items-center gap-3 p-4">
              <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-emerald-500/10 text-emerald-600">
                <Banknote className="h-4 w-4" />
              </div>

              <div className="min-w-0">
                <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                  Price
                </p>

                <p className="truncate text-sm font-semibold">
                  {previewPrice || "Not set"}
                </p>
              </div>
            </CardContent>
          </Card>

          <Card className="rounded-2xl border bg-card/70 shadow-sm">
            <CardContent className="flex items-center gap-3 p-4">
              <div
                  className={`flex h-9 w-9 items-center justify-center rounded-xl ${
                      form.active
                          ? "bg-emerald-500/10 text-emerald-600"
                          : "bg-muted text-muted-foreground"
                  }`}
              >
                <ShieldCheck className="h-4 w-4" />
              </div>

              <div className="min-w-0">
                <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                  Publishing
                </p>

                <p className="text-sm font-semibold">
                  {form.active ? "Ready to publish" : "Draft mode"}
                </p>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* ------------------------------------------------------------------ */}
        {/* Main command center                                                 */}
        {/* ------------------------------------------------------------------ */}

        <div className="grid items-start gap-6 xl:grid-cols-[minmax(0,1fr)_340px]">
          {/* ================================================================= */}
          {/* MAIN FORM                                                         */}
          {/* ================================================================= */}

          <div className="space-y-5">
            {/* Identity ----------------------------------------------------- */}

            <Section
                icon={Compass}
                title="Tour identity"
                description="Define the core information guests will see first."
                status={
                  sectionStatus.identity
                      ? "complete"
                      : "incomplete"
                }
            >
              <div className="grid gap-5 sm:grid-cols-2">
                <Field
                    label="Tour name"
                    required
                    count={form.name.length}
                    limit={LIMITS.name}
                >
                  <Input
                      value={form.name}
                      onChange={(event) =>
                          set("name", event.target.value)
                      }
                      placeholder="e.g. Maasai Mara Migration Safari"
                      maxLength={LIMITS.name}
                      className="h-11 border-none bg-muted/50 shadow-none"
                  />
                </Field>

                <Field label="Category" required>
                  <Select
                      value={form.category}
                      onValueChange={(value) =>
                          set(
                              "category",
                              value as TourCategory
                          )
                      }
                  >
                    <SelectTrigger className="h-11 border-none bg-muted/50 shadow-none">
                      <SelectValue placeholder="Choose a category" />
                    </SelectTrigger>

                    <SelectContent>
                      {CATEGORIES.map((category) => (
                          <SelectItem
                              key={category.value}
                              value={category.value}
                          >
                            {category.label}
                          </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </Field>

                <Field label="Short description" required>
                  <Textarea
                      value={form.shortDescription}
                      onChange={(event) =>
                          set(
                              "shortDescription",
                              event.target.value
                          )
                      }
                      placeholder="A concise description shown on cards and search results."
                      maxLength={LIMITS.shortDescription}
                      className="min-h-[90px] resize-none border-none bg-muted/50 shadow-none"
                  />
                </Field>

                <Field label="Best season">
                  <Input
                      value={form.bestSeason}
                      onChange={(event) =>
                          set(
                              "bestSeason",
                              event.target.value
                          )
                      }
                      placeholder="e.g. July — October"
                      className="h-11 border-none bg-muted/50 shadow-none"
                  />
                </Field>

                <Field
                    label="Full description"
                    required
                    count={form.description.length}
                    limit={LIMITS.description}
                >
                  <Textarea
                      value={form.description}
                      onChange={(event) =>
                          set(
                              "description",
                              event.target.value
                          )
                      }
                      placeholder="Tell the complete story of the experience..."
                      maxLength={LIMITS.description}
                      className="min-h-[180px] resize-y border-none bg-muted/50 shadow-none sm:min-h-[200px]"
                  />
                </Field>
              </div>
            </Section>

            {/* Destination ------------------------------------------------- */}

            <Section
                icon={Map}
                title="Destination"
                description="Specify where the experience takes place and where guests meet."
                status={
                  sectionStatus.destination
                      ? "complete"
                      : "incomplete"
                }
            >
              <div className="grid gap-5 sm:grid-cols-2">
                <Field
                    label="Destination"
                    required
                    count={form.destination.length}
                    limit={LIMITS.destination}
                >
                  <Input
                      value={form.destination}
                      onChange={(event) =>
                          set(
                              "destination",
                              event.target.value
                          )
                      }
                      placeholder="e.g. Maasai Mara"
                      maxLength={LIMITS.destination}
                      className="h-11 border-none bg-muted/50 shadow-none"
                  />
                </Field>

                <Field
                    label="Country"
                    required
                    count={form.country.length}
                    limit={LIMITS.country}
                >
                  <Input
                      value={form.country}
                      onChange={(event) =>
                          set(
                              "country",
                              event.target.value
                          )
                      }
                      maxLength={LIMITS.country}
                      className="h-11 border-none bg-muted/50 shadow-none"
                  />
                </Field>

                <Field
                    label="Region"
                    count={form.region.length}
                    limit={LIMITS.region}
                >
                  <Input
                      value={form.region}
                      onChange={(event) =>
                          set("region", event.target.value)
                      }
                      placeholder="e.g. Narok County"
                      maxLength={LIMITS.region}
                      className="h-11 border-none bg-muted/50 shadow-none"
                  />
                </Field>

                <Field
                    label="Meeting point"
                    count={form.meetingPoint.length}
                    limit={LIMITS.meetingPoint}
                >
                  <Input
                      value={form.meetingPoint}
                      onChange={(event) =>
                          set(
                              "meetingPoint",
                              event.target.value
                          )
                      }
                      placeholder="e.g. Wilson Airport, Nairobi"
                      maxLength={LIMITS.meetingPoint}
                      className="h-11 border-none bg-muted/50 shadow-none"
                  />
                </Field>
              </div>
            </Section>

            {/* Trip --------------------------------------------------------- */}

            <Section
                icon={Clock}
                title="Trip details"
                description="Duration, difficulty, capacity and guest suitability."
                status={
                  sectionStatus.trip
                      ? "complete"
                      : "incomplete"
                }
            >
              <div className="grid gap-5 sm:grid-cols-2 lg:grid-cols-4">
                <Field label="Days" required>
                  <Input
                      type="number"
                      min={1}
                      max={365}
                      value={form.durationDays}
                      onChange={(event) =>
                          set(
                              "durationDays",
                              event.target.value
                          )
                      }
                      placeholder="e.g. 5"
                      className="h-11 border-none bg-muted/50 shadow-none"
                  />
                </Field>

                <Field label="Nights" required>
                  <Input
                      type="number"
                      min={0}
                      max={365}
                      value={form.durationNights}
                      onChange={(event) =>
                          set(
                              "durationNights",
                              event.target.value
                          )
                      }
                      placeholder="e.g. 4"
                      className="h-11 border-none bg-muted/50 shadow-none"
                  />
                </Field>

                <Field label="Minimum age">
                  <Input
                      type="number"
                      min={1}
                      value={form.minimumAge}
                      onChange={(event) =>
                          set(
                              "minimumAge",
                              event.target.value
                          )
                      }
                      placeholder="No minimum"
                      className="h-11 border-none bg-muted/50 shadow-none"
                  />
                </Field>

                <Field label="Max group size">
                  <Input
                      type="number"
                      min={1}
                      max={1000}
                      value={form.maxGroupSize}
                      onChange={(event) =>
                          set(
                              "maxGroupSize",
                              event.target.value
                          )
                      }
                      placeholder="Unlimited"
                      className="h-11 border-none bg-muted/50 shadow-none"
                  />
                </Field>

                <div className="sm:col-span-2 lg:col-span-4">
                  <Field label="Difficulty" required>
                    <Select
                        value={form.difficulty}
                        onValueChange={(value) =>
                            set(
                                "difficulty",
                                value as TourDifficulty
                            )
                        }
                    >
                      <SelectTrigger className="h-11 border-none bg-muted/50 shadow-none">
                        <SelectValue placeholder="How demanding is this tour?" />
                      </SelectTrigger>

                      <SelectContent>
                        {DIFFICULTIES.map((difficulty) => (
                            <SelectItem
                                key={difficulty.value}
                                value={difficulty.value}
                            >
                              {difficulty.label}
                            </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </Field>
                </div>
              </div>
            </Section>

            {/* Pricing ------------------------------------------------------ */}

            <Section
                icon={Banknote}
                title="Pricing"
                description="Set the public price, charging model and booking deposit."
                status={
                  sectionStatus.pricing
                      ? "complete"
                      : "incomplete"
                }
            >
              <div className="grid gap-5 sm:grid-cols-3">
                <Field label="Price" required>
                  <Input
                      type="number"
                      min={0}
                      step="0.01"
                      value={form.price}
                      onChange={(event) =>
                          set("price", event.target.value)
                      }
                      placeholder="0.00"
                      className="h-11 border-none bg-muted/50 font-mono shadow-none"
                  />
                </Field>

                <Field label="Currency" required>
                  <Select
                      value={form.currency}
                      onValueChange={(value) =>
                          set(
                              "currency",
                              value as TourCurrency
                          )
                      }
                  >
                    <SelectTrigger className="h-11 border-none bg-muted/50 shadow-none">
                      <SelectValue />
                    </SelectTrigger>

                    <SelectContent>
                      {CURRENCIES.map((currency) => (
                          <SelectItem
                              key={currency.value}
                              value={currency.value}
                          >
                            {currency.label}
                          </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </Field>

                <Field label="Charged" required>
                  <Select
                      value={form.priceType}
                      onValueChange={(value) =>
                          set(
                              "priceType",
                              value as TourPriceType
                          )
                      }
                  >
                    <SelectTrigger className="h-11 border-none bg-muted/50 shadow-none">
                      <SelectValue />
                    </SelectTrigger>

                    <SelectContent>
                      {PRICE_TYPES.map((priceType) => (
                          <SelectItem
                              key={priceType.value}
                              value={priceType.value}
                          >
                            {priceType.label}
                          </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </Field>

                <div className="sm:col-span-3">
                  <div className="rounded-xl bg-muted/40 p-4">
                    <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
                      <div>
                        <p className="text-sm font-medium">
                          Booking deposit
                        </p>

                        <p className="mt-0.5 text-xs text-muted-foreground">
                          Percentage required to confirm a booking.
                        </p>
                      </div>

                      <div className="flex items-center gap-3">
                        <Input
                            type="number"
                            min={0}
                            max={100}
                            value={form.depositPercentage}
                            onChange={(event) =>
                                set(
                                    "depositPercentage",
                                    event.target.value
                                )
                            }
                            className="h-10 w-24 border-none bg-background shadow-none"
                        />

                        <span className="text-sm text-muted-foreground">
                        %
                      </span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </Section>

            {/* Content ------------------------------------------------------ */}

            <Section
                icon={ListChecks}
                title="Experience content"
                description="Build the guest-facing itinerary and booking information."
                status={
                  sectionStatus.content
                      ? "complete"
                      : undefined
                }
            >
              <div className="space-y-6">
                <Field label="Highlights">
                  <TagListField
                      values={form.highlights}
                      onChange={(next) =>
                          set("highlights", next)
                      }
                      placeholder="e.g. Witness the wildebeest migration"
                      emptyHint="Add short, scannable reasons guests should book this experience."
                  />
                </Field>

                <Separator />

                <Field label="Day-by-day itinerary">
                  <ItineraryField
                      values={form.itinerary}
                      onChange={(next) =>
                          set("itinerary", next)
                      }
                  />
                </Field>

                <Separator />

                <div className="grid gap-6 lg:grid-cols-2">
                  <Field label="Inclusions">
                    <TagListField
                        values={form.inclusions}
                        onChange={(next) =>
                            set("inclusions", next)
                        }
                        placeholder="e.g. Park entry fees"
                        emptyHint="What is covered in the price."
                    />
                  </Field>

                  <Field label="Exclusions">
                    <TagListField
                        values={form.exclusions}
                        onChange={(next) =>
                            set("exclusions", next)
                        }
                        placeholder="e.g. International flights"
                        emptyHint="What guests need to arrange themselves."
                    />
                  </Field>
                </div>

                <Separator />

                <Field label="Requirements">
                  <TagListField
                      values={form.requirements}
                      onChange={(next) =>
                          set("requirements", next)
                      }
                      placeholder="e.g. Valid yellow fever certificate"
                      emptyHint="Anything guests must bring, hold or meet."
                  />
                </Field>

                <Separator />

                <Field
                    label="Important information"
                    count={form.importantInformation.length}
                    limit={LIMITS.importantInformation}
                >
                  <Textarea
                      value={form.importantInformation}
                      onChange={(event) =>
                          set(
                              "importantInformation",
                              event.target.value
                          )
                      }
                      placeholder="Health advisories, weather, visa notes, arrival information..."
                      maxLength={LIMITS.importantInformation}
                      className="min-h-[130px] resize-y border-none bg-muted/50 shadow-none"
                  />
                </Field>
              </div>
            </Section>

            {/* Media -------------------------------------------------------- */}

            <Section
                icon={ImagePlus}
                title="Media"
                description="Give the tour a strong visual identity."
                status={
                  sectionStatus.media
                      ? "complete"
                      : "incomplete"
                }
            >
              <div className="grid gap-5 lg:grid-cols-2">
                <div className="space-y-5">
                  <Field label="Cover image URL" required>
                    <Input
                        value={form.coverImage}
                        onChange={(event) =>
                            set(
                                "coverImage",
                                event.target.value
                            )
                        }
                        placeholder="https://..."
                        className="h-11 border-none bg-muted/50 shadow-none"
                    />
                  </Field>

                  <Field label="Video URL">
                    <div className="relative">
                      <Video className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />

                      <Input
                          value={form.videoUrl}
                          onChange={(event) =>
                              set(
                                  "videoUrl",
                                  event.target.value
                              )
                          }
                          placeholder="https://..."
                          className="h-11 border-none bg-muted/50 pl-9 shadow-none"
                      />
                    </div>
                  </Field>
                </div>

                <Field label="Gallery images">
                  <TagListField
                      values={form.galleryImages}
                      onChange={(next) =>
                          set("galleryImages", next)
                      }
                      placeholder="https://... press Enter"
                      emptyHint="Additional images displayed on the tour detail page."
                  />
                </Field>
              </div>
            </Section>

            {/* Publishing --------------------------------------------------- */}

            <Section
                icon={ShieldCheck}
                title="Publishing"
                description="Control visibility and catalogue placement."
            >
              <div className="grid gap-3 md:grid-cols-2">
                <div className="flex items-center justify-between gap-4 rounded-2xl bg-muted/40 p-4">
                  <div className="flex items-start gap-3">
                    <div
                        className={`mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg ${
                            form.active
                                ? "bg-emerald-500/10 text-emerald-600"
                                : "bg-muted text-muted-foreground"
                        }`}
                    >
                      <ShieldCheck className="h-4 w-4" />
                    </div>

                    <div>
                      <p className="text-sm font-medium">
                        Active
                      </p>

                      <p className="mt-0.5 text-xs leading-relaxed text-muted-foreground">
                        Make this tour visible and bookable.
                      </p>
                    </div>
                  </div>

                  <Switch
                      checked={form.active}
                      onCheckedChange={(checked) =>
                          set("active", checked)
                      }
                  />
                </div>

                <div className="flex items-center justify-between gap-4 rounded-2xl bg-muted/40 p-4">
                  <div className="flex items-start gap-3">
                    <div className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-amber-500/10 text-amber-600">
                      <Star className="h-4 w-4" />
                    </div>

                    <div>
                      <p className="text-sm font-medium">
                        Featured
                      </p>

                      <p className="mt-0.5 text-xs leading-relaxed text-muted-foreground">
                        Highlight this tour in priority areas.
                      </p>
                    </div>
                  </div>

                  <Switch
                      checked={form.featured}
                      onCheckedChange={(checked) =>
                          set("featured", checked)
                      }
                  />
                </div>
              </div>
            </Section>

            {/* Bottom action bar ------------------------------------------- */}

            <div className="flex flex-col gap-3 rounded-2xl border bg-card p-4 shadow-sm sm:flex-row sm:items-center sm:justify-between">
              <div className="flex items-start gap-2">
                <Info className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" />

                <p className="text-xs leading-relaxed text-muted-foreground">
                  Required sections must be completed before the
                  tour can be created.
                </p>
              </div>

              <div className="flex gap-2">
                <Button
                    asChild
                    type="button"
                    variant="ghost"
                    size="sm"
                >
                  <Link href="/tours">
                    Cancel
                  </Link>
                </Button>

                <Button
                    type="submit"
                    size="sm"
                    disabled={isSubmitting}
                >
                  {isSubmitting ? (
                      <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                      <Sparkles className="h-3.5 w-3.5" />
                  )}

                  {isSubmitting
                      ? "Creating..."
                      : "Create tour"}
                </Button>
              </div>
            </div>
          </div>

          {/* ================================================================= */}
          {/* COMMAND SIDEBAR                                                   */}
          {/* ================================================================= */}

          <aside className="space-y-5 xl:sticky xl:top-6">
            {/* Progress ----------------------------------------------------- */}

            <Card className="overflow-hidden rounded-2xl shadow-sm">
              <CardHeader className="space-y-3 pb-3">
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="text-sm">
                      Tour setup
                    </CardTitle>

                    <CardDescription className="mt-0.5 text-xs">
                      Required information
                    </CardDescription>
                  </div>

                  <div className="text-right">
                    <p className="font-mono text-sm font-semibold">
                      {progress}%
                    </p>

                    <p className="text-[10px] text-muted-foreground">
                      complete
                    </p>
                  </div>
                </div>

                <div className="h-2 overflow-hidden rounded-full bg-muted">
                  <div
                      className="h-full rounded-full bg-primary transition-all duration-500"
                      style={{
                        width: `${progress}%`,
                      }}
                  />
                </div>
              </CardHeader>

              <CardContent className="space-y-1 pb-4">
                {[
                  {
                    key: "identity",
                    label: "Tour identity",
                  },
                  {
                    key: "destination",
                    label: "Destination",
                  },
                  {
                    key: "trip",
                    label: "Trip details",
                  },
                  {
                    key: "pricing",
                    label: "Pricing",
                  },
                  {
                    key: "media",
                    label: "Cover image",
                  },
                ].map((item) => {
                  const done =
                      sectionStatus[
                          item.key as keyof typeof sectionStatus
                          ];

                  return (
                      <div
                          key={item.key}
                          className="flex items-center gap-2.5 rounded-lg px-2 py-2"
                      >
                        {done ? (
                            <div className="flex h-5 w-5 items-center justify-center rounded-full bg-emerald-500/10 text-emerald-600">
                              <Check className="h-3 w-3" />
                            </div>
                        ) : (
                            <div className="h-5 w-5 rounded-full border border-muted-foreground/20" />
                        )}

                        <span
                            className={`flex-1 text-xs ${
                                done
                                    ? "font-medium text-foreground"
                                    : "text-muted-foreground"
                            }`}
                        >
                      {item.label}
                    </span>

                        {done && (
                            <ChevronRight className="h-3.5 w-3.5 text-muted-foreground/30" />
                        )}
                      </div>
                  );
                })}
              </CardContent>
            </Card>

            {/* Live preview ------------------------------------------------- */}

            <Card className="overflow-hidden rounded-2xl shadow-sm">
              <div className="relative aspect-[16/10] overflow-hidden bg-muted">
                {form.coverImage ? (
                    <>
                      {/* eslint-disable-next-line @next/next/no-img-element */}
                      <img
                          src={form.coverImage}
                          alt=""
                          className="h-full w-full object-cover"
                          onError={(event) => {
                            event.currentTarget.style.display =
                                "none";
                          }}
                      />

                      <div className="absolute inset-x-0 bottom-0 h-20 bg-gradient-to-t from-black/60 to-transparent" />

                      {form.active && (
                          <Badge className="absolute left-3 top-3 rounded-full border-none bg-background/90 text-[10px] text-foreground shadow-sm backdrop-blur">
                            <span className="mr-1.5 h-1.5 w-1.5 rounded-full bg-emerald-500" />
                            Active
                          </Badge>
                      )}
                    </>
                ) : (
                    <div className="flex h-full flex-col items-center justify-center gap-2 text-muted-foreground/40">
                      <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-dashed">
                        <ImagePlus className="h-5 w-5" />
                      </div>

                      <p className="text-[11px]">
                        Cover image preview
                      </p>
                    </div>
                )}
              </div>

              <CardContent className="space-y-4 p-4">
                <div className="space-y-2">
                  <div className="flex items-start justify-between gap-3">
                    <h3 className="min-w-0 flex-1 truncate text-sm font-semibold">
                      {form.name || "Untitled tour"}
                    </h3>

                    {form.category && (
                        <Badge
                            variant="outline"
                            className={`shrink-0 rounded-full border-none text-[10px] font-medium ${
                                CATEGORY_STYLES[
                                    form.category
                                    ] ??
                                "bg-muted text-muted-foreground"
                            }`}
                        >
                          {form.category}
                        </Badge>
                    )}
                  </div>

                  {form.destination && (
                      <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
                        <Map className="h-3.5 w-3.5" />
                        {form.destination}
                        {form.country
                            ? `, ${form.country}`
                            : ""}
                      </p>
                  )}
                </div>

                {form.shortDescription && (
                    <p className="line-clamp-3 text-xs leading-relaxed text-muted-foreground">
                      {form.shortDescription}
                    </p>
                )}

                <Separator />

                <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
                  <PreviewStat
                      icon={Clock}
                      value={
                        form.durationDays
                            ? `${form.durationDays} days`
                            : "— days"
                      }
                  />

                  <PreviewStat
                      icon={Users}
                      value={
                        form.maxGroupSize
                            ? `max ${form.maxGroupSize}`
                            : "No limit"
                      }
                  />

                  <PreviewStat
                      icon={Mountain}
                      value={
                        form.difficulty
                            ? form.difficulty.toLowerCase()
                            : "—"
                      }
                  />
                </div>

                {previewPrice && (
                    <div className="flex items-end justify-between gap-3 pt-1">
                      <div>
                        <p className="text-[10px] uppercase tracking-wide text-muted-foreground">
                          Starting from
                        </p>

                        <p className="font-mono text-base font-semibold">
                          {previewPrice}
                        </p>
                      </div>

                      <span className="text-[10px] text-muted-foreground">
                    {form.priceType
                        ?.replaceAll("_", " ")
                        .toLowerCase()}
                  </span>
                    </div>
                )}
              </CardContent>
            </Card>

            {/* Publishing status ------------------------------------------- */}

            <Card className="rounded-2xl shadow-sm">
              <CardContent className="space-y-4 p-4">
                <div className="flex items-center gap-2">
                  <ShieldCheck className="h-4 w-4 text-primary" />

                  <p className="text-xs font-semibold">
                    Publishing status
                  </p>
                </div>

                <div className="space-y-2">
                  <div className="flex items-center justify-between rounded-lg bg-muted/40 px-3 py-2.5">
                  <span className="text-xs text-muted-foreground">
                    Catalogue visibility
                  </span>

                    <Badge
                        variant="outline"
                        className={
                          form.active
                              ? "rounded-full border-emerald-500/20 bg-emerald-500/10 text-[10px] text-emerald-700 dark:text-emerald-400"
                              : "rounded-full border-none bg-muted text-[10px]"
                        }
                    >
                      {form.active
                          ? "Active"
                          : "Hidden"}
                    </Badge>
                  </div>

                  <div className="flex items-center justify-between rounded-lg bg-muted/40 px-3 py-2.5">
                  <span className="text-xs text-muted-foreground">
                    Homepage feature
                  </span>

                    <Badge
                        variant="outline"
                        className={
                          form.featured
                              ? "rounded-full border-amber-500/20 bg-amber-500/10 text-[10px] text-amber-700 dark:text-amber-400"
                              : "rounded-full border-none bg-muted text-[10px]"
                        }
                    >
                      {form.featured
                          ? "Featured"
                          : "Standard"}
                    </Badge>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Warning ------------------------------------------------------ */}

            {!form.coverImage && (
                <div className="flex items-start gap-2.5 rounded-2xl border border-amber-200 bg-amber-50 p-4 text-xs text-amber-800 dark:border-amber-900/60 dark:bg-amber-950/30 dark:text-amber-400">
                  <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />

                  <div>
                    <p className="font-medium">
                      Cover image required
                    </p>

                    <p className="mt-1 leading-relaxed opacity-80">
                      Add a cover image before creating the
                      tour.
                    </p>
                  </div>
                </div>
            )}
          </aside>
        </div>
      </form>
  );
}
