import axios, { AxiosError, InternalAxiosRequestConfig } from "axios"
import type { ApiError } from "@/types"

const BASE_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:4000/api"

export const apiClient = axios.create({
  baseURL: BASE_URL,
  timeout: 15_000,
  headers: { "Content-Type": "application/json" },
})

// ─── Request interceptor — attach access token ───────────────────────────────
apiClient.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  if (typeof window !== "undefined") {
    const raw = sessionStorage.getItem("auth-session")
    if (raw) {
      try {
        const session = JSON.parse(raw)
        const token = session?.state?.tokens?.accessToken
        if (token) config.headers.Authorization = `Bearer ${token}`
      } catch {
        // ignore
      }
    }
  }
  return config
})

// ─── Response interceptor — refresh token on 401 ────────────────────────────
let isRefreshing = false
let failedQueue: Array<{ resolve: (v: unknown) => void; reject: (e: unknown) => void }> = []

function processQueue(error: AxiosError | null, token: string | null = null) {
  failedQueue.forEach((p) => (error ? p.reject(error) : p.resolve(token)))
  failedQueue = []
}

apiClient.interceptors.response.use(
  (res) => res,
  async (error: AxiosError) => {
    const original = error.config as InternalAxiosRequestConfig & { _retry?: boolean }
    if (error.response?.status === 401 && !original._retry) {
      if (isRefreshing) {
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject })
        }).then((token) => {
          original.headers.Authorization = `Bearer ${token}`
          return apiClient(original)
        })
      }
      original._retry = true
      isRefreshing = true
      try {
        const raw = sessionStorage.getItem("auth-session")
        const session = raw ? JSON.parse(raw) : null
        const refreshToken = session?.state?.tokens?.refreshToken
        const { data } = await axios.post(`${BASE_URL}/auth/refresh`, { refreshToken })
        const newToken = data.accessToken
        // persist
        if (session?.state) {
          session.state.tokens.accessToken = newToken
          sessionStorage.setItem("auth-session", JSON.stringify(session))
        }
        processQueue(null, newToken)
        original.headers.Authorization = `Bearer ${newToken}`
        return apiClient(original)
      } catch (refreshError) {
        processQueue(refreshError as AxiosError, null)
        sessionStorage.removeItem("auth-session")
        window.location.href = "/login"
        return Promise.reject(refreshError)
      } finally {
        isRefreshing = false
      }
    }
    // Normalise error shape
    const apiErr: ApiError = {
      message: (error.response?.data as any)?.message ?? error.message,
      code: (error.response?.data as any)?.code,
      statusCode: error.response?.status,
      errors: (error.response?.data as any)?.errors,
    }
    return Promise.reject(apiErr)
  }
)

export default apiClient
