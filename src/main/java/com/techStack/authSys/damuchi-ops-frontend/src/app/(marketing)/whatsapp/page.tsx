import { redirect } from "next/navigation";

export default function WhatsAppPage() {
    redirect(
        "https://wa.me/254700000000?text=Hello%20Damuchi%20Safaris"
    );
}