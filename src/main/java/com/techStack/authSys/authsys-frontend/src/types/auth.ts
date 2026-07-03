// ─────────────────────────────────────────────────────────────────
// Auth types — mirrors actual backend DTOs exactly
// ─────────────────────────────────────────────────────────────────

export type Role =
    | "SUPER_ADMIN"
    | "ADMIN"
    | "MANAGER"
    | "DESIGNER"
    | "USER"
    | "GUEST";

export type AccountStatus =
    | "ACTIVE"
    | "PENDING_APPROVAL"
    | "REJECTED"
    | "LOCKED"
    | "DISABLED";

export interface User {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  phoneNumber: string;
  roles: Role[];
  status: AccountStatus;
  forcePasswordChange: boolean;
  phoneVerified: boolean;
  emailVerified: boolean;
  firstTimeSetupCompleted: boolean;
  firstTimeSetupCompletedAt?: string;
  passwordLastChanged?: string;
  createdAt: string;
  lastLoginAt?: string;
}

export interface UserProfile extends User {}

export interface UserUpdateRequest {
  firstName?: string;
  lastName?: string;
  phoneNumber?: string;
}

export interface PendingUser {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  phoneNumber: string;
  roles: Role[];
  status: AccountStatus;
  createdAt: string;
}

export interface UserPermissions {
  userId: string;
  email: string;
  roles: Role[];
  permissions: string[];
  effectivePermissions: string[];
}

export interface Permission {
  id: string;
  name: string;
  description: string;
  resource: string;
  action: string;
}

export interface RolePermissions {
  role: Role;
  permissions: string[];
  permissionCount: number;
}

// ── com.techStack.authSys.models.auth.TokenPair ──────────────────
export interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

// ── com.techStack.authSys.dto.response.LoginResponse (record) ───
// Uses boolean flags, NOT a status string enum.
// Fields match the Java record constructor order exactly.
export interface LoginResponse {
  success: boolean;
  firstTimeLogin: boolean;
  requiresOtp: boolean;
  rateLimited: boolean;
  temporaryToken: string | null;
  userId: string | null;
  accessToken: string | null;
  refreshToken: string | null;
  user: Partial<User> | null;
  message: string;
}

export interface ApiResponse<T> {
  success: boolean;
  message: string;
  data: T;
}

// ── com.techStack.authSys.dto.response.OtpResult ────────────────
export interface OtpResult {
  sent: boolean;
  rateLimited: boolean;
  message: string;
  otp?: string; // @JsonIgnore on backend — never serialized
}

// ── com.techStack.authSys.dto.response.OtpVerificationResult ────
export interface OtpVerificationResult {
  valid: boolean;
  expired: boolean;
  attemptsExceeded: boolean;
  remainingAttempts: number;
  message: string;
  verificationToken?: string;
  expiresInSeconds?: number;
}

// ── com.techStack.authSys.dto.response.LoginOtpResponse ─────────
export interface LoginOtpResponse {
  status: "OTP_SENT" | "RATE_LIMITED";
  tempToken?: string;
  userId?: string;
  message: string;
}

// ── Request DTOs ─────────────────────────────────────────────────
// Mirrors com.techStack.authSys.dto.request.LoginRequest (record)
export interface LoginRequest {
  email: string;
  password: string;
}

export interface RegisterRequest {
  email: string;
  password: string;
  firstName: string;
  lastName: string;
  phoneNumber: string;
}

export interface ChangePasswordRequest {
  newPassword: string;
  confirmPassword: string;
}

export interface VerifyOtpRequest {
  otp: string;
}

export interface VerifyLoginOtpRequest {
  otp: string;
}

export interface ForgotPasswordRequest {
  email: string;
}

export interface ResetPasswordRequest {
  token: string;
  newPassword: string;
}

export interface PasswordChangeRequest {
  currentPassword: string;
  newPassword: string;
}

// ── com.techStack.authSys.dto.response.ApiResponse ───────────────
export interface RegistrationResponse {
  success?: boolean;
  status?: "PENDING_APPROVAL" | "SUCCESS";
  message: string;
  userId?: string;
}

// ── Audit ────────────────────────────────────────────────────────
export interface AuditLog {
  id: string;
  userId: string;
  userEmail?: string;
  action: string;
  actionType: string;
  entityType?: string;
  entityId?: string;
  details?: Record<string, unknown>;
  ipAddress?: string;
  deviceFingerprint?: string;
  severity: "INFO" | "WARN" | "ERROR";
  timestamp: string;
}

// ── Error shape from GlobalExceptionHandler ───────────────────────
export interface ApiError {
  status: number;
  error: string;
  message: string;
  timestamp: string;
  path?: string;
}

// ── Pagination ────────────────────────────────────────────────────
export interface Page<T> {
  content: T[];
  totalElements: number;
  totalPages: number;
  pageNumber: number;
  pageSize: number;
  last: boolean;
  first: boolean;
}