import { Badge } from "@/components/ui/Badge";
import type { BookingStatus } from "@/types";

const STATUS_TONE: Record<BookingStatus, "neutral" | "savanna" | "amber" | "red" | "blue"> = {
    PENDING_PAYMENT: "amber",
    CONFIRMED: "savanna",
    CANCELLED: "neutral",
    COMPLETED: "blue",
    REFUNDED: "red",
};

const STATUS_LABEL: Record<BookingStatus, string> = {
    PENDING_PAYMENT: "Pending payment",
    CONFIRMED: "Confirmed",
    CANCELLED: "Cancelled",
    COMPLETED: "Completed",
    REFUNDED: "Refunded",
};

interface BookingStatusBadgeProps {
    status: BookingStatus;
}

export function BookingStatusBadge({ status }: BookingStatusBadgeProps) {
    return <Badge tone={STATUS_TONE[status]}>{STATUS_LABEL[status]}</Badge>;
}