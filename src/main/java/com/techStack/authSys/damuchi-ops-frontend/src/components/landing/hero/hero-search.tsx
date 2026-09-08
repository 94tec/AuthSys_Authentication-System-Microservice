"use client";

import { Search, MapPin } from "lucide-react";
import { Button } from "@/components/ui/button";

import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from "@/components/ui/select";

import {
    CATEGORY_LABELS,
} from "@/types/tour";

interface Props {
    search: string;
    category: string;
    onSearchChange: (value: string) => void;
    onCategoryChange: (value: string) => void;
    onSearch: () => void;
}

export function HeroSearch({
                               search,
                               category,
                               onSearchChange,
                               onCategoryChange,
                               onSearch,
                           }: Props) {
    return (
        <div
            className="
        rounded-3xl
        border border-white/10
        bg-white/5
        p-3
        backdrop-blur-2xl
        shadow-[0_20px_80px_rgba(0,0,0,.25)]
      "
        >
            <div className="flex flex-col gap-3 lg:flex-row">
                <div
                    className="
            flex flex-1 items-center gap-3
            rounded-2xl
            bg-expedition-sand
            px-4 py-3
          "
                >
                    <Search className="h-4 w-4 text-expedition-forest/50" />

                    <input
                        value={search}
                        onChange={(e) =>
                            onSearchChange(e.target.value)
                        }
                        onKeyDown={(e) =>
                            e.key === "Enter" && onSearch()
                        }
                        placeholder="Search destinations, tours..."
                        className="
              w-full
              bg-transparent
              text-expedition-forest
              outline-none
            "
                    />
                </div>

                <Select
                    value={category}
                    onValueChange={onCategoryChange}
                >
                    <SelectTrigger className="h-[52px] w-full bg-expedition-sand lg:w-60">
                        <div className="flex items-center gap-2">
                            <MapPin className="h-4 w-4" />
                            <SelectValue placeholder="Experience" />
                        </div>
                    </SelectTrigger>

                    <SelectContent>
                        {Object.entries(CATEGORY_LABELS).map(
                            ([value, label]) => (
                                <SelectItem
                                    key={value}
                                    value={value}
                                >
                                    {label}
                                </SelectItem>
                            )
                        )}
                    </SelectContent>
                </Select>

                <Button
                    size="lg"
                    onClick={onSearch}
                    className="
            h-[52px]
            rounded-2xl
            bg-gradient-to-r
            from-amber-500
            via-orange-500
            to-amber-600
            text-white
          "
                >
                    Explore Adventures
                </Button>
            </div>
        </div>
    );
}