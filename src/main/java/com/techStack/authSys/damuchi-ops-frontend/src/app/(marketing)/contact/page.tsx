import {
    Clock3,
    Mail,
    MapPin,
    MessageCircle,
    Phone,
} from "lucide-react";

import { Navbar } from "@/components/layout/navbar";
import { Footer } from "@/components/layout/footer";
import { EnquiryBand } from "@/components/landing/enquiry/enquiry-band";

export default function ContactPage() {
    return (
        <div className="flex min-h-screen flex-col bg-background">
            <Navbar />

            <main className="flex-1">
                {/* Hero */}
                <section className="relative overflow-hidden border-b bg-gray-950 py-20 text-white sm:py-28">
                    <div
                        aria-hidden="true"
                        className="absolute inset-0 bg-[radial-gradient(circle_at_top_right,rgba(249,115,22,0.18),transparent_40%)]"
                    />

                    <div className="container relative">
                        <p className="font-mono text-xs uppercase tracking-[0.18em] text-amber-400">
                            Contact Damuchi Safaris
                        </p>

                        <h1 className="mt-3 max-w-4xl font-display text-4xl font-semibold tracking-tight sm:text-5xl lg:text-6xl">
                            Let's plan your next adventure.
                        </h1>

                        <p className="mt-5 max-w-2xl text-base leading-8 text-white/70">
                            Whether you're dreaming of a luxury safari,
                            gorilla trekking expedition, beach escape,
                            or a custom East African itinerary, our
                            team is ready to help.
                        </p>
                    </div>
                </section>

                {/* Content */}
                <section className="container py-16 sm:py-20">
                    <div className="grid gap-10 lg:grid-cols-[1fr_420px]">
                        {/* Form */}
                        <div>
                            <EnquiryBand />
                        </div>

                        {/* Contact Info */}
                        <aside className="space-y-6">
                            <div className="rounded-3xl border bg-card p-6">
                                <h2 className="text-lg font-semibold">
                                    Get in touch
                                </h2>

                                <div className="mt-6 space-y-5">
                                    <div className="flex gap-3">
                                        <Phone className="mt-0.5 h-5 w-5 text-accent" />
                                        <div>
                                            <p className="font-medium">
                                                Phone
                                            </p>
                                            <p className="text-sm text-muted-foreground">
                                                +254 700 000 000
                                            </p>
                                        </div>
                                    </div>

                                    <div className="flex gap-3">
                                        <Mail className="mt-0.5 h-5 w-5 text-accent" />
                                        <div>
                                            <p className="font-medium">
                                                Email
                                            </p>
                                            <p className="text-sm text-muted-foreground">
                                                hello@damuchi.com
                                            </p>
                                        </div>
                                    </div>

                                    <div className="flex gap-3">
                                        <MessageCircle className="mt-0.5 h-5 w-5 text-accent" />
                                        <div>
                                            <p className="font-medium">
                                                WhatsApp
                                            </p>
                                            <p className="text-sm text-muted-foreground">
                                                Available daily
                                            </p>
                                        </div>
                                    </div>

                                    <div className="flex gap-3">
                                        <MapPin className="mt-0.5 h-5 w-5 text-accent" />
                                        <div>
                                            <p className="font-medium">
                                                Office
                                            </p>
                                            <p className="text-sm text-muted-foreground">
                                                Mombasa, Kenya
                                            </p>
                                        </div>
                                    </div>

                                    <div className="flex gap-3">
                                        <Clock3 className="mt-0.5 h-5 w-5 text-accent" />
                                        <div>
                                            <p className="font-medium">
                                                Response Time
                                            </p>
                                            <p className="text-sm text-muted-foreground">
                                                Usually within 2 hours
                                            </p>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <div className="rounded-3xl border bg-accent/5 p-6">
                                <h3 className="font-semibold">
                                    Planning a custom trip?
                                </h3>

                                <p className="mt-2 text-sm text-muted-foreground">
                                    Tell us where you'd like to go,
                                    when you're travelling, and your
                                    approximate budget. We'll create
                                    recommendations tailored to you.
                                </p>
                            </div>
                        </aside>
                    </div>
                </section>
            </main>

            <Footer />
        </div>
    );
}