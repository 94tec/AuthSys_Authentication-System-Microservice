import { Testimonials } from "@/components/landing/testimonials";
import {Navbar} from "@/components/layout/navbar";
import {Footer} from "@/components/layout/footer";

export default function TestimonialsPage() {
    return (
        <>
            <Navbar/>

            <main>
                <section className="py-20 text-center">
                    <h1 className="font-display text-5xl font-semibold">
                        Guest Reviews
                    </h1>
                </section>

                <Testimonials/>
            </main>

            <Footer/>
        </>
    );
}