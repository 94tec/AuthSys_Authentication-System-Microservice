import { apiClient } from "@/lib/api-client";
import type {  AuthTokens, LoginRequest, RegisterRequest, User } from "@/types/index-types";

export interface LoginResponse {
  accessToken: string;
  refreshToken: string;
  user: User;
  firstTimeLogin?: boolean;
  requiresOtp?: boolean;
  temporaryToken?: string;
}

interface ApiResponse<T> {
  success: boolean;
  message: string;
  data: T;
  timestamp?: string;
  error?: string;
}
// ───────────────────────────────────────────────────────────── // Normalized API error // ─────────────────────────────────────────────────────────────
export class AuthApiError extends Error {
  status: number;
  code?: string;
  timestamp?: string;
  constructor(
      message: string,
      status = 400,
      code?: string,
      timestamp?: string
  ) {
    super(message);
    this.name = "AuthApiError";
    this.status = status;
    this.code = code;
    this.timestamp = timestamp;
    Object.setPrototypeOf(this, AuthApiError.prototype);
  }
}
// ────────────────────── // Response unwrapping // ────────────────────────────
async function unwrap<T>(
    promise: Promise<{ data: ApiResponse<T> }>
): Promise<T> {
  const response = await promise;
  const wrapper = response.data;
  if (!wrapper) {
    throw new AuthApiError(
        "The server returned an empty response.",
        502
    );
  }
  if (!wrapper.success) {
    throw new AuthApiError(
        wrapper.message || wrapper.error || "Request failed.",
        400,
        wrapper.error,
        wrapper.timestamp
    );
  }
  return wrapper.data;
}

export const authApi = {
  login: async (req: LoginRequest): Promise<LoginResponse> => {
    const res = await apiClient.post<ApiResponse<LoginResponse>>("/auth/login", req);
    return res.data.data ?? (res.data as unknown as LoginResponse);
  },

  register: async (req: RegisterRequest): Promise<ApiResponse<void>> => {
    const res = await apiClient.post<ApiResponse<void>>("/auth/register", req);
    return res.data;
  },

  refresh: async (refreshToken: string): Promise<AuthTokens> => {
    const res = await apiClient.post<ApiResponse<AuthTokens>>("/auth/refresh", { refreshToken });
    return res.data.data;
  },

  logout: async (): Promise<void> => {
    await apiClient.post("/auth/logout");
  },

  me: async (): Promise<User> => {
    const res = await apiClient.get<ApiResponse<User>>("/auth/me");
    return res.data.data;
  },
  // ============================================================
  // CURRENT USER
  // ============================================================
  getCurrentUser: async (): Promise<User> =>
      unwrap<User>(
          apiClient.get("/auth/me")
      ),
};
