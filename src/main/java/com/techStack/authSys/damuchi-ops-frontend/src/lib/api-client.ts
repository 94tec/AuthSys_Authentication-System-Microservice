import axios, { AxiosError, type InternalAxiosRequestConfig } from "axios";
import type { ApiError } from "@/types";
import { useAuthStore } from "@/store/auth-store";

const BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8001/api";
console.log("[api-client] base URL:", BASE_URL);

export const apiClient = axios.create({
  baseURL: BASE_URL,
  timeout: 30_000,
  headers: { "Content-Type": "application/json" },
});

// ── Request interceptor — attach access token ─────────────────────────────────
// Reads from useAuthStore.getState() (the in-memory Zustand value) rather than
// parsing sessionStorage directly. persist() writes to sessionStorage
// asynchronously after set() runs, so a request fired in the same tick as
// login/refresh could read a stale or empty value from storage — the same
// race class as the tempToken/safeNavigate bug in authsys. getState() is
// always current because it reads the live store, not its serialized copy.
apiClient.interceptors.request.use(
    (config: InternalAxiosRequestConfig) => {
      const token = useAuthStore.getState().accessToken;
      if (token && config.headers && !config.headers["Authorization"]) {
        config.headers["Authorization"] = `Bearer ${token}`;
      }

      if (process.env.NODE_ENV === "development") {
        console.log(`[api-client] → ${config.method?.toUpperCase()} ${config.url}`);
      }
      return config;
    },
    (error) => Promise.reject(error)
);

// ── Response interceptor — normalize errors, handle 401 refresh ──────────────
apiClient.interceptors.response.use(
    (response) => {
      if (process.env.NODE_ENV === "development") {
        console.log(`[api-client] ← ${response.status} ${response.config.url}`);
      }
      return response;
    },
    async (error: AxiosError<ApiError>) => {
      const original = error.config as InternalAxiosRequestConfig & { _retry?: boolean };
      const status = error.response?.status;

      // 401 + not already retried + not an auth endpoint itself
      if (
          status === 401 &&
          !original?._retry &&
          !original?.url?.includes("/auth/")
      ) {
        original._retry = true;
        try {
          const refreshToken = useAuthStore.getState().refreshToken;
          if (!refreshToken) {
            throw new Error("No refresh token");
          }

          const res = await axios.post(`${BASE_URL}/auth/refresh`, { refreshToken });
          const { accessToken, refreshToken: newRefresh } = res.data.data ?? res.data;

          // Write through the store's own setter — this both updates the
          // in-memory value read by the request interceptor above AND lets
          // Zustand's persist middleware handle the sessionStorage write
          // (and the damuchi-has-session cookie) the same way it does on
          // login, instead of hand-editing serialized JSON out-of-band.
          useAuthStore.getState().setTokens({
            accessToken,
            refreshToken: newRefresh ?? refreshToken,
          });

          original.headers!["Authorization"] = `Bearer ${accessToken}`;
          return apiClient(original);
        } catch {
          // Refresh failed — clear session and redirect to login
          useAuthStore.getState().clearSession();
          if (typeof window !== "undefined") {
            window.location.href = "/login";
          }
          return Promise.reject(normalizeError(error));
        }
      }

      return Promise.reject(normalizeError(error));
    }
);

function normalizeError(error: AxiosError<ApiError>): ApiError {
  if (error.response?.data?.message) {
    return {
      message: error.response.data.message,
      status: error.response.status,
      errorCode: error.response.data.errorCode,
    };
  }
  if (error.code === "ECONNABORTED") {
    return { message: "Request timed out. Please try again.", status: 408 };
  }
  if (!error.response) {
    console.error("[api-client] NETWORK ERROR — no response received.");
    return { message: "Network error. Is the backend running?", status: 0 };
  }
  return { message: error.message || "An unexpected error occurred.", status: error.response?.status };
}