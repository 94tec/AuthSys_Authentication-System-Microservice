import { redirect } from "next/navigation";

// Root — redirect to login. Middleware handles auth'd users to /dashboard.
export default function RootPage() {
  redirect("/app");
}

