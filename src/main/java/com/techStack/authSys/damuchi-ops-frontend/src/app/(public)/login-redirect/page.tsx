import { AuthSuspense } from "@/components/auth/auth-suspense";
import LoginRedirect from "./LoginRedirect";

export default function LoginRedirectPage() {
    return (
        <AuthSuspense>
            <LoginRedirect />
        </AuthSuspense>
    );
}