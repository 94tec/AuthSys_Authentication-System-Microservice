import apiClient from "./client"
import type {
  LoginRequest, LoginResponse, RegisterRequest,
  OtpVerifyRequest, AuthSession, ChangePasswordRequest,
  ResetPasswordRequest, ForgotPasswordRequest,
} from "@/types"

export const authApi = {
  login: (data: LoginRequest) =>
    apiClient.post<LoginResponse>("/auth/login", data).then((r) => r.data),

  register: (data: RegisterRequest) =>
    apiClient.post<{ message: string }>("/auth/register", data).then((r) => r.data),

  verifyOtp: (data: OtpVerifyRequest) =>
    apiClient.post<AuthSession>("/auth/verify-otp", data).then((r) => r.data),

  resendOtp: (tempToken: string) =>
    apiClient.post<{ message: string }>("/auth/resend-otp", { tempToken }).then((r) => r.data),

  changePassword: (data: ChangePasswordRequest) =>
    apiClient.post<{ message: string; tempToken?: string }>("/auth/change-password", data).then((r) => r.data),

  setupComplete: (tempToken: string) =>
    apiClient.post<AuthSession>("/auth/setup-complete", { tempToken }).then((r) => r.data),

  forgotPassword: (data: ForgotPasswordRequest) =>
    apiClient.post<{ message: string }>("/auth/forgot-password", data).then((r) => r.data),

  resetPassword: (data: ResetPasswordRequest) =>
    apiClient.post<{ message: string }>("/auth/reset-password", data).then((r) => r.data),

  logout: () =>
    apiClient.post("/auth/logout").then((r) => r.data),

  me: () =>
    apiClient.get<AuthSession["user"]>("/auth/me").then((r) => r.data),
}
