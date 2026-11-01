import axios, { AxiosError, type InternalAxiosRequestConfig } from "axios";
import type { ApiError } from "@/types/index-types";
import { useAuthStore } from "@/store/auth-store";
import { endSession } from "@/lib/end-session";

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
let isRefreshing = false;
let refreshQueue: Array<(token: string | null) => void> = [];

function drain(token: string | null) {
    refreshQueue.forEach((cb) => cb(token));
    refreshQueue = [];
}

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

        if (status === 401 && !original?._retry && !original?.url?.includes("/auth/")) {
            original._retry = true;

            const refreshToken = useAuthStore.getState().refreshToken;
            if (!refreshToken) {
                endSession("expired");
                return Promise.reject(normalizeError(error));
            }

            if (isRefreshing) {
                return new Promise((resolve, reject) => {
                    refreshQueue.push((newToken) => {
                        if (newToken) {
                            original.headers!["Authorization"] = `Bearer ${newToken}`;
                            resolve(apiClient(original));
                        } else {
                            reject(normalizeError(error));
                        }
                    });
                });
            }

            isRefreshing = true;
            try {
                const res = await axios.post(`${BASE_URL}/auth/refresh`, { refreshToken });
                const { accessToken, refreshToken: newRefresh } = res.data.data ?? res.data;

                useAuthStore.getState().setTokens({
                    accessToken,
                    refreshToken: newRefresh ?? refreshToken,
                });

                drain(accessToken);
                original.headers!["Authorization"] = `Bearer ${accessToken}`;
                return apiClient(original);
            } catch {
                drain(null);
                endSession("expired");
                return Promise.reject(normalizeError(error));
            } finally {
                isRefreshing = false;
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