import { Skeleton } from "@/components/ui/skeleton";

export function TourCardSkeleton() {
    return (
        <article
            aria-hidden="true"
            className="
                group
                flex
                h-full
                min-w-0
                flex-col
                overflow-hidden
                rounded-3xl
                border
                border-border/70
                bg-card
                shadow-sm
            "
        >
            {/* Image */}
            <div className="relative aspect-[16/10] w-full overflow-hidden sm:aspect-[16/9]">
                <Skeleton className="h-full w-full rounded-none" />

                {/* Fake image controls */}
                <div className="absolute inset-x-0 top-0 flex items-center justify-between p-4">
                    <Skeleton className="h-7 w-24 rounded-full bg-white/20" />
                    <Skeleton className="h-7 w-16 rounded-full bg-white/20" />
                </div>
            </div>

            {/* Body */}
            <div className="flex flex-1 flex-col p-5 sm:p-6">
                {/* Destination */}
                <Skeleton className="h-3.5 w-32" />

                {/* Title */}
                <div className="mt-3 space-y-2">
                    <Skeleton className="h-5 w-[92%]" />
                    <Skeleton className="h-5 w-[68%]" />
                </div>

                {/* Description */}
                <div className="mt-3 space-y-2">
                    <Skeleton className="h-3.5 w-full" />
                    <Skeleton className="h-3.5 w-[82%]" />
                </div>

                {/* Metadata */}
                <div className="mt-5 flex flex-wrap gap-2">
                    <Skeleton className="h-6 w-20 rounded-full" />
                    <Skeleton className="h-6 w-24 rounded-full" />
                </div>

                {/* Divider */}
                <div className="my-5 h-px bg-border/60" />

                {/* Footer */}
                <div className="mt-auto flex items-end justify-between gap-4">
                    <div className="min-w-0 space-y-2">
                        <Skeleton className="h-2.5 w-10" />
                        <Skeleton className="h-7 w-32" />
                        <Skeleton className="h-2.5 w-20" />
                    </div>

                    <Skeleton className="h-10 w-24 shrink-0 rounded-full" />
                </div>
            </div>
        </article>
    );
}