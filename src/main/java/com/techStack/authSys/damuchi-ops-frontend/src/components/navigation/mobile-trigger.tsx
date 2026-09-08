"use client";

import { Menu } from "lucide-react";

interface Props {
    onClick: () => void;
}

export function MobileTrigger({ onClick }: Props) {
    return (
        <button
            onClick={onClick}
            className="
                rounded-xl
                p-2
                transition-colors
                hover:bg-muted
                lg:hidden
            "
        >
            <Menu className="h-6 w-6" />
        </button>
    );
}