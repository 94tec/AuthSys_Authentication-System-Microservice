import { AuthSuspense } from "@/components/auth/auth-suspense";
import AuthCallback from "./AuthCallback"
export default function AuthCallbackPage() {
    return (
        <AuthSuspense>
            <AuthCallback />
        </AuthSuspense>
    );
}