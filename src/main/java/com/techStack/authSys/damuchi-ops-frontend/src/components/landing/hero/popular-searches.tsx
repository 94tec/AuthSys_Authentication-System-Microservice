"use client";

const POPULAR = [
    "Masai Mara",
    "Amboseli",
    "Diani Beach",
    "Zanzibar",
    "Mount Kenya",
];

interface Props {
    onSelect: (value: string) => void;
}

export function PopularSearches({ onSelect }: Props) {
    return (
        <div className="mt-5 flex flex-wrap items-center justify-center gap-2">
      <span className="text-xs text-expedition-sand/50">
        Popular:
      </span>

            {POPULAR.map((item) => (
                <button
                    key={item}
                    onClick={() => onSelect(item)}
                    className="
            rounded-full
            border border-white/10
            bg-white/5
            px-3 py-1
            text-xs
            text-expedition-sand/80
            transition-all
            hover:bg-white/10
          "
                >
                    {item}
                </button>
            ))}
        </div>
    );
}