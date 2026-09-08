import {TravelContentPage} from "@/components/travel/travel-content-page";

export const metadata = {
    title: "Visa Information",
    description:
        "Travel visa requirements for East African destinations.",
};

export default function VisaInformationPage() {
    return (
        <TravelContentPage
            title="Visa Information"
            description="Entry requirements for Kenya, Tanzania, Uganda and Rwanda."
        />
    );
}