import { apiClient } from "@/lib/api-client";
import type {
  ChangePasswordRequest,
  ForgotPasswordRequest,
  LoginRequest,
  LoginResponse,
  OtpResult,
  OtpVerificationResult,
  PasswordChangeRequest,
  RegisterRequest,
  RegistrationResponse,
  ResetPasswordRequest,
  TokenPair,
  UserProfile,
  UserUpdateRequest,
  VerifyLoginOtpRequest,
  VerifyOtpRequest,
} from "@/types/auth";

// ─────────────────────────────────────────────────────────────────
// ApiResponse wrapper — your backend wraps every response in:
// { success: boolean, message: string, data: T, timestamp: string }
// We unwrap it here so callers always get T directly.
// ─────────────────────────────────────────────────────────────────
interface ApiResponse<T> {
  success: boolean;
  message: string;
  data: T;
  timestamp?: string;
  error?: string;
}

async function unwrap<T>(promise: Promise<{ data: ApiResponse<T> }>): Promise<T> {
  const { data: wrapper } = await promise;
  // If backend returned an error wrapper, throw it so catch blocks handle it
  if (!wrapper.success && wrapper.error) {
    throw {
      status: 400,
      error: wrapper.error,
      message: wrapper.message,
      timestamp: wrapper.timestamp ?? new Date().toISOString(),
    };
  }
  return wrapper.data;
}

export const authApi = {
  // ── AuthController ──────────────────────────────────────────────
  register: async (p: RegisterRequest): Promise<RegistrationResponse> =>
      (await apiClient.post<RegistrationResponse>("/auth/register", p)).data,

  // Login is wrapped in ApiResponse<LoginResponse>
  login: async (p: LoginRequest): Promise<LoginResponse> =>
      unwrap<LoginResponse>(apiClient.post("/auth/login", p)),

  logout: async (): Promise<void> => {
    await apiClient.post("/auth/logout");
  },

  refreshToken: async (refreshToken: string): Promise<TokenPair> =>
      (await apiClient.post<TokenPair>("/auth/refresh", { refreshToken })).data,

  getCurrentUser: async (): Promise<UserProfile> =>
      (await apiClient.get<UserProfile>("/auth/me")).data,

  // ── GoogleAuthController ────────────────────────────────────────
  googleLogin: async (idToken: string): Promise<LoginResponse> =>
      unwrap<LoginResponse>(apiClient.post("/auth/google/login", { idToken })),

  // ── FirstTimeSetupController ────────────────────────────────────
  // Your backend endpoint uses Authorization header with the temp Bearer token
  // Request body: only newPassword (confirmPassword is frontend-only validation)

  // Step 1: POST /api/auth/first-time-setup/change-password
  changePasswordFirstTime: async (
      tempToken: string,
      p: ChangePasswordRequest
  ): Promise<OtpResult> =>
      unwrap<OtpResult>(
          apiClient.post("/auth/first-time-setup/change-password", p, {
            headers: { Authorization: `Bearer ${tempToken}` },
          })
      ),

  // Step 2: POST /api/auth/first-time-setup/verify-otp
  verifyOtpFirstTime: async (
      tempToken: string,
      p: VerifyOtpRequest
  ): Promise<OtpVerificationResult> =>
      unwrap<OtpVerificationResult>(
          apiClient.post("/auth/first-time-setup/verify-otp", p, {
            headers: { Authorization: `Bearer ${tempToken}` },
          })
      ),

  // POST /api/auth/first-time-setup/resend-otp
  resendSetupOtp: async (tempToken: string): Promise<OtpResult> =>
      unwrap<OtpResult>(
          apiClient.post(
              "/auth/first-time-setup/resend-otp",
              {},
              { headers: { Authorization: `Bearer ${tempToken}` } }
          )
      ),

  // Step 3: POST /api/auth/first-time-setup/complete
  completeSetup: async (verificationToken: string): Promise<TokenPair> =>
      unwrap<TokenPair>(
          apiClient.post("/auth/first-time-setup/complete", { verificationToken })
      ),

  // ── OtpController (login 2FA) ───────────────────────────────────
  verifyLoginOtp: async (
      tempToken: string,
      p: VerifyLoginOtpRequest
  ): Promise<TokenPair> =>
      unwrap<TokenPair>(
          apiClient.post("/auth/login-otp/verify", p, {
            headers: { "X-Temp-Token": tempToken },
          })
      ),

  resendLoginOtp: async (tempToken: string): Promise<OtpResult> =>
      unwrap<OtpResult>(
          apiClient.post(
              "/auth/login-otp/resend",
              {},
              { headers: { "X-Temp-Token": tempToken } }
          )
      ),

  // ── PasswordResetController ─────────────────────────────────────
  forgotPassword: async (p: ForgotPasswordRequest): Promise<{ message: string }> =>
      (await apiClient.post<{ message: string }>("/auth/forgot-password", p)).data,

  resetPassword: async (p: ResetPasswordRequest): Promise<{ message: string }> =>
      (await apiClient.post<{ message: string }>("/auth/reset-password", p)).data,

  // ── PasswordManagementController ────────────────────────────────
  changePassword: async (p: PasswordChangeRequest): Promise<{ message: string }> =>
      (await apiClient.post<{ message: string }>("/user/password/change", p)).data,

  // ── UserProfileController ────────────────────────────────────────
  getProfile: async (): Promise<UserProfile> =>
      (await apiClient.get<UserProfile>("/user/profile")).data,

  updateProfile: async (p: UserUpdateRequest): Promise<UserProfile> =>
      (await apiClient.patch<UserProfile>("/user/profile", p)).data,
};