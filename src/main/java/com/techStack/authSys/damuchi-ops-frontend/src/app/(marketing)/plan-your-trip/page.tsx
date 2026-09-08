import { Navbar } from "@/components/layout/navbar";
import { Footer } from "@/components/layout/footer";
import { CtaBand } from "@/components/landing/cta-band";

export default function PlanYourTripPage() {
    return (
        <>
            <Navbar />

            <main>
                <section className="border-b bg-gray-950 py-20 text-white">
                    <div className="container">
                        <h1 className="font-display text-5xl font-semibold">
                            Plan Your Trip
                        </h1>

                        <p className="mt-4 max-w-2xl text-white/70">
                            Everything you need before travelling through
                            Kenya, Tanzania, Uganda, and Rwanda.
                        </p>
                    </div>
                </section>

                <section className="container py-16">
                    <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
                        {/* cards */}
                    </div>
                </section>

                <CtaBand />
            </main>

            <Footer />
        </>
    );
}