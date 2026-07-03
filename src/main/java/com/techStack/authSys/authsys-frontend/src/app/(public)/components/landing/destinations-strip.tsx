const DESTINATIONS = [
  {
    name: "Maasai Mara",
    country: "Kenya",
    tag: "Safari & Wildlife",
    gradient: "from-amber-700/40 to-expedition-forest/60",
  },
  {
    name: "Diani Beach",
    country: "Kenya",
    tag: "Beach & Coast",
    gradient: "from-sky-600/30 to-expedition-forest/60",
  },
  {
    name: "Mount Kenya",
    country: "Kenya",
    tag: "Mountain & Trekking",
    gradient: "from-expedition-moss/50 to-expedition-forest/70",
  },
  {
    name: "Lamu Old Town",
    country: "Kenya",
    tag: "Cultural & Heritage",
    gradient: "from-expedition-clay/40 to-expedition-forest/60",
  },
];

export function DestinationsStrip() {
  return (
    <section id="destinations" className="container py-16 sm:py-20">
      <div className="flex flex-col items-start justify-between gap-4 sm:flex-row sm:items-end">
        <div>
          <p className="font-mono text-xs uppercase tracking-[0.15em] text-accent">
            Where to next
          </p>
          <h2 className="mt-2 font-display text-3xl font-medium tracking-tight sm:text-4xl">
            Destinations our travelers return to.
          </h2>
        </div>
      </div>

      <div className="mt-10 grid grid-cols-2 gap-4 lg:grid-cols-4">
        {DESTINATIONS.map((dest) => (
          <div
            key={dest.name}
            className={`group relative flex h-56 flex-col justify-end overflow-hidden rounded-xl bg-gradient-to-br p-4 ${dest.gradient}`}
          >
            <div
              className="absolute inset-0 opacity-20 transition-transform duration-500 group-hover:scale-110"
              style={{
                backgroundImage:
                  "radial-gradient(circle at 30% 30%, white 0.5px, transparent 0.5px)",
                backgroundSize: "18px 18px",
              }}
              aria-hidden="true"
            />
            <p className="relative font-mono text-[10px] uppercase tracking-wider text-expedition-sand/70">
              {dest.tag}
            </p>
            <h3 className="relative mt-1 font-display text-lg font-medium tracking-tight text-expedition-sand">
              {dest.name}
            </h3>
            <p className="relative text-xs text-expedition-sand/60">{dest.country}</p>
          </div>
        ))}
      </div>
    </section>
  );
}
