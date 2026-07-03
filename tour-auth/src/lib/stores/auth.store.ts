"use client"
import { create } from "zustand"
import { persist, createJSONStorage } from "zustand/middleware"
import type { User, AuthTokens } from "@/types"

interface AuthState {
  user: User | null
  tokens: AuthTokens | null
  tempToken: string | null
  isAuthenticated: boolean
  // Actions
  setSession: (user: User, tokens: AuthTokens) => void
  setTempToken: (token: string | null) => void
  clearSession: () => void
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      user: null,
      tokens: null,
      tempToken: null,
      isAuthenticated: false,

      setSession: (user, tokens) => {
        // Set a lightweight cookie so middleware can gate routes server-side
        document.cookie = `auth-token=${tokens.accessToken}; path=/; SameSite=Lax; max-age=${tokens.expiresIn}`
        set({ user, tokens, isAuthenticated: true, tempToken: null })
      },

      setTempToken: (token) => set({ tempToken: token }),

      clearSession: () => {
        document.cookie = "auth-token=; path=/; max-age=0"
        set({ user: null, tokens: null, tempToken: null, isAuthenticated: false })
      },
    }),
    {
      name: "auth-session",
      storage: createJSONStorage(() =>
        typeof window !== "undefined" ? sessionStorage : { getItem: () => null, setItem: () => {}, removeItem: () => {} }
      ),
      partialize: (state) => ({ user: state.user, tokens: state.tokens }),
    }
  )
)
