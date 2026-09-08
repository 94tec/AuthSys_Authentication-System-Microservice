import Link from "next/link";
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from "@/components/ui/Table";
import { EmptyState } from "@/components/ui/EmptyState";
import { BookingStatusBadge } from "@/components/bookings/BookingStatusBadge";
import { BookOpen } from "lucide-react";
import type { Booking } from "@/types";

interface BookingsTableProps {
    bookings: Booking[];
}

export function BookingsTable({ bookings }: BookingsTableProps) {
    if (bookings.length === 0) {
        return (
            <EmptyState
                icon={BookOpen}
                title="No bookings yet"
                description="Bookings will show up here once customers start reserving tours."
            />
        );
    }

    return (
        <Table>
            <TableHeader>
                <TableRow>
                    <TableHead>Customer</TableHead>
                    <TableHead>Tour</TableHead>
                    <TableHead>Date</TableHead>
                    <TableHead>Travelers</TableHead>
                    <TableHead>Total</TableHead>
                    <TableHead>Status</TableHead>
                </TableRow>
            </TableHeader>
            <TableBody>
                {bookings.map((b) => (
                    <TableRow key={b.id}>
                        <TableCell>
                            <Link href={`/staff/bookings/${b.id}`} className="font-medium text-earth hover:text-savanna">
                                {b.customerName}
                            </Link>
                            <p className="text-2xs text-stone/50">{b.customerEmail}</p>
                        </TableCell>
                        <TableCell>{b.tourName}</TableCell>
                        <TableCell>{new Date(b.tourDate).toLocaleDateString()}</TableCell>
                        <TableCell>{b.travelerCount}</TableCell>
                        <TableCell className="font-medium text-earth">
                            {b.currency} {b.totalPrice.toLocaleString()}
                        </TableCell>
                        <TableCell>
                            <BookingStatusBadge status={b.status} />
                        </TableCell>
                    </TableRow>
                ))}
            </TableBody>
        </Table>
    );
}