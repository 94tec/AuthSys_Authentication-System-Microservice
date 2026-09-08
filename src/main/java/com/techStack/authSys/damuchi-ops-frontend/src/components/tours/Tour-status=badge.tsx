import { Badge } from "@/components/ui/badge";
import type { TourAdmin } from "@/types";

interface TourStatusBadgeProps {
    tour: Pick<TourAdmin, "active" | "deleted">;
}

export function TourStatusBadge({ tour }: TourStatusBadgeProps) {
    if (tour.deleted) return <Badge tone="red">Deleted</Badge>;
    if (!tour.active) return <Badge tone="neutral">Inactive</Badge>;
    return <Badge tone="savanna">Active</Badge>;
}