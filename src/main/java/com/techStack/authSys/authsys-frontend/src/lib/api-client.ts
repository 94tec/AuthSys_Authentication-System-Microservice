import axios, {
  type AxiosError,
  type AxiosInstance,
  type InternalAxiosRequestConfig,
} from "axios";
import type { ApiError, TokenPair } from "@/types/auth";

// Port 8001 confirmed from startup log: "Netty started on port 8001"
const API_BASE_URL =
    process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8001/api";

if (process.env.NODE_ENV === "development") {
  console.log("[api-client] base URL:", API_BASE_URL);
}

export const apiClient: AxiosInstance = axios.create({
  baseURL: API_BASE_URL,
  timeout: 20_000, // 20s — your login takes ~11s in logs
  headers: { "Content-Type": "application/json" },
  withCredentials: false, // Spring WebFlux CORS must allow origin 3000
});

// ── Attach JWT on every outgoing request ────────────────────────
apiClient.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  if (process.env.NODE_ENV === "development") {
    console.log(`[api-client] → ${config.method?.toUpperCase()} ${config.baseURL}${config.url}`);
  }
  try {
    const raw = sessionStorage.getItem("authsys-session");
    if (raw) {
      const parsed = JSON.parse(raw) as { state?: { accessToken?: string } };
      const token = parsed?.state?.accessToken;
      if (token && config.headers) {
        config.headers.Authorization = `Bearer ${token}`;
      }
    }
  } catch {
    // sessionStorage unavailable in SSR — skip
  }
  return config;
});

// ── 401 → refresh → retry ───────────────────────────────────────
let isRefreshing = false;
let refreshQueue: Array<(token: string | null) => void> = [];

function drain(token: string | null) {
  refreshQueue.forEach((cb) => cb(token));
  refreshQueue = [];
}

apiClient.interceptors.response.use(
    (r) => {
      if (process.env.NODE_ENV === "development") {
        console.log(`[api-client] ← ${r.status} ${r.config.url}`);
      }
      return r;
    },
    async (error: AxiosError<ApiError>) => {
      const original = error.config as InternalAxiosRequestConfig & { _retry?: boolean };
      const status = error.response?.status;

      if (process.env.NODE_ENV === "development") {
        if (!error.response) {
          // Network error — almost always CORS or backend not running
          console.error(
              "[api-client] NETWORK ERROR — no response received.\n" +
              "Possible causes:\n" +
              "  1. Backend not running on port 8001\n" +
              "  2. CORS blocking requests from http://localhost:3000\n" +
              "     → Add to your Spring WebFlux SecurityConfig: .cors(cors -> cors.configurationSource(...))\n" +
              "     → Or in WebClientConfig: allow origin http://localhost:3000\n" +
              `  3. Wrong API URL in .env.local (currently: ${API_BASE_URL})\n`,
              error.message
          );
        } else {
          console.error(`[api-client] ← ${status} ${original?.url}`, error.response?.data);
        }
      }

      const isAuthPath = original?.url?.includes("/auth/");

      if (status === 401 && !original?._retry && !isAuthPath) {
        let refreshToken: string | null = null;
        try {
          const raw = sessionStorage.getItem("authsys-session");
          if (raw) {
            const parsed = JSON.parse(raw) as { state?: { refreshToken?: string } };
            refreshToken = parsed?.state?.refreshToken ?? null;
          }
        } catch { /* SSR */ }

        if (!refreshToken) {
          sessionStorage.removeItem("authsys-session");
          if (typeof window !== "undefined") window.location.href = "/login";
          return Promise.reject(normalizeError(error));
        }

        if (isRefreshing) {
          return new Promise((resolve, reject) =>
              refreshQueue.push((newToken) => {
                if (newToken && original) {
                  original.headers!.Authorization = `Bearer ${newToken}`;
                  original._retry = true;
                  resolve(apiClient(original));
                } else {
                  reject(normalizeError(error));
                }
              })
          );
        }

        isRefreshing = true;
        try {
          const { data } = await axios.post<TokenPair>(
              `${API_BASE_URL}/auth/refresh`,
              { refreshToken }
          );
          try {
            const raw = sessionStorage.getItem("authsys-session");
            if (raw) {
              const parsed = JSON.parse(raw) as { state?: Record<string, unknown> };
              if (parsed.state) {
                parsed.state.accessToken = data.accessToken;
                parsed.state.refreshToken = data.refreshToken;
                sessionStorage.setItem("authsys-session", JSON.stringify(parsed));
              }
            }
          } catch { /* SSR */ }
          drain(data.accessToken);
          if (original) {
            original.headers!.Authorization = `Bearer ${data.accessToken}`;
            original._retry = true;
            return apiClient(original);
          }
        } catch {
          drain(null);
          sessionStorage.removeItem("authsys-session");
          if (typeof window !== "undefined") window.location.href = "/login";
          return Promise.reject(normalizeError(error));
        } finally {
          isRefreshing = false;
        }
      }

      return Promise.reject(normalizeError(error));
    }
);

export function normalizeError(error: AxiosError<ApiError>): ApiError {
  if (!error.response) {
    return {
      status: 0,
      error: "Network Error",
      message:
          "Can't reach the server. Check: (1) authSys running on port 8001, " +
          "(2) CORS allows http://localhost:3000, " +
          "(3) NEXT_PUBLIC_API_BASE_URL in .env.local is correct.",
      timestamp: new Date().toISOString(),
    };
  }
  if (error.response?.data?.message) return error.response.data;
  if (error.code === "ECONNABORTED") {
    return {
      status: 408,
      error: "Timeout",
      message: `Request timed out after ${20}s. Your login took ~11s in logs — check if Redis is slow.`,
      timestamp: new Date().toISOString(),
    };
  }
  return {
    status: error.response.status,
    error: error.response.statusText,
    message: "Something went wrong. Please try again.",
    timestamp: new Date().toISOString(),
  };
}