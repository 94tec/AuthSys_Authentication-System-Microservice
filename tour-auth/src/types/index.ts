// ─── User & Auth ────────────────────────────────────────────────────────────

export type UserRole = "ADMIN" | "MANAGER" | "STAFF" | "GUIDE"

export type UserStatus =
  | "PENDING_APPROVAL"
  | "PENDING_SETUP"
  | "ACTIVE"
  | "LOCKED"
  | "REJECTED"

export interface User {
  id: string
  email: string
  firstName: string
  lastName: string
  role: UserRole
  status: UserStatus
  profileImage?: string
  createdAt: string
  updatedAt: string
  lastLoginAt?: string
}

export interface AuthTokens {
  accessToken: string
  refreshToken: string
  expiresIn: number
}

export interface AuthSession {
  user: User
  tokens: AuthTokens
}

// ─── API Shapes ─────────────────────────────────────────────────────────────

export interface LoginRequest {
  email: string
  password: string
}

export interface LoginResponse {
  requiresOtp: boolean
  tempToken?: string
  session?: AuthSession
}

export interface RegisterRequest {
  email: string
  firstName: string
  lastName: string
  role: UserRole
}

export interface OtpVerifyRequest {
  otp: string
  tempToken: string
}

export interface ChangePasswordRequest {
  currentPassword: string
  newPassword: string
  confirmPassword: string
}

export interface ResetPasswordRequest {
  token: string
  newPassword: string
  confirmPassword: string
}

export interface ForgotPasswordRequest {
  email: string
}

// ─── Admin ───────────────────────────────────────────────────────────────────

export interface PendingUser extends User {
  registeredAt: string
  requestNote?: string
}

export interface ApprovalAction {
  userId: string
  action: "APPROVE" | "REJECT"
  reason?: string
}

// ─── Tours ───────────────────────────────────────────────────────────────────

export type TourStatus = "DRAFT" | "PUBLISHED" | "ARCHIVED"
export type TourDifficulty = "EASY" | "MODERATE" | "CHALLENGING" | "EXTREME"

export interface Tour {
  id: string
  title: string
  slug: string
  description: string
  duration: number // days
  difficulty: TourDifficulty
  status: TourStatus
  price: number
  capacity: number
  coverImage?: string
  startDate?: string
  endDate?: string
  createdAt: string
  updatedAt: string
  guideId?: string
}

// ─── API Errors ──────────────────────────────────────────────────────────────

export interface ApiError {
  message: string
  code?: string
  statusCode?: number
  errors?: Record<string, string[]>
}

// ─── Pagination ──────────────────────────────────────────────────────────────

export interface PaginatedResponse<T> {
  data: T[]
  total: number
  page: number
  pageSize: number
  totalPages: number
}
