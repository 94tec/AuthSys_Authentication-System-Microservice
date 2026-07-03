import { z } from "zod";

// ─────────────────────────────────────────────────────────────────
// Password schema — mirrors PasswordPolicyService rules
// Min 10 chars confirmed from ChangePasswordRequest validation
// ─────────────────────────────────────────────────────────────────
export const passwordSchema = z
  .string()
  .min(10, "Use at least 10 characters")
  .max(72, "Keep it under 72 characters")
  .regex(/[A-Z]/, "Include at least one uppercase letter")
  .regex(/[a-z]/, "Include at least one lowercase letter")
  .regex(/[0-9]/, "Include at least one number")
  .regex(/[^A-Za-z0-9]/, "Include at least one symbol (!@#$%…)");

export const emailSchema = z
  .string()
  .min(1, "Email is required")
  .email("Enter a valid email address");

// Phone: Africa's Talking SMS — +254 format expected
export const phoneSchema = z
  .string()
  .min(1, "Phone number is required")
  .regex(/^\+?[1-9]\d{7,14}$/, "Enter a valid phone number with country code (+254…)");

// ── Auth forms ───────────────────────────────────────────────────
export const loginSchema = z.object({
  email: emailSchema,
  password: z.string().min(1, "Password is required"),
});

export const registerSchema = z
  .object({
    firstName: z.string().min(1, "First name is required").max(50),
    lastName: z.string().min(1, "Last name is required").max(50),
    email: emailSchema,
    phoneNumber: phoneSchema,
    password: passwordSchema,
    confirmPassword: z.string().min(1, "Confirm your password"),
  })
  .refine((d) => d.password === d.confirmPassword, {
    message: "Passwords don't match",
    path: ["confirmPassword"],
  });

// FirstTimeLoginSetupService Step 1
export const changePasswordSchema = z
  .object({
    newPassword: passwordSchema,
    confirmPassword: z.string().min(1, "Confirm your password"),
  })
  .refine((d) => d.newPassword === d.confirmPassword, {
    message: "Passwords don't match",
    path: ["confirmPassword"],
  });

// OtpService — 6 digit numeric
export const otpSchema = z.object({
  otp: z
    .string()
    .length(6, "Enter the 6-digit code")
    .regex(/^\d{6}$/, "Code must be numbers only"),
});

// PasswordResetController
export const forgotPasswordSchema = z.object({
  email: emailSchema,
});

export const resetPasswordSchema = z
  .object({
    newPassword: passwordSchema,
    confirmPassword: z.string().min(1, "Confirm your password"),
  })
  .refine((d) => d.newPassword === d.confirmPassword, {
    message: "Passwords don't match",
    path: ["confirmPassword"],
  });

// PasswordManagementController — PasswordChangeRequest
export const passwordChangeSchema = z
  .object({
    currentPassword: z.string().min(1, "Current password is required"),
    newPassword: passwordSchema,
    confirmPassword: z.string().min(1, "Confirm your new password"),
  })
  .refine((d) => d.newPassword === d.confirmPassword, {
    message: "Passwords don't match",
    path: ["confirmPassword"],
  });

// UserProfileController — UserUpdateDTO
export const profileUpdateSchema = z.object({
  firstName: z.string().min(1, "First name is required").max(50),
  lastName: z.string().min(1, "Last name is required").max(50),
  phoneNumber: phoneSchema,
});

export type LoginFormValues = z.infer<typeof loginSchema>;
export type RegisterFormValues = z.infer<typeof registerSchema>;
export type ChangePasswordFormValues = z.infer<typeof changePasswordSchema>;
export type OtpFormValues = z.infer<typeof otpSchema>;
export type ForgotPasswordFormValues = z.infer<typeof forgotPasswordSchema>;
export type ResetPasswordFormValues = z.infer<typeof resetPasswordSchema>;
export type PasswordChangeFormValues = z.infer<typeof passwordChangeSchema>;
export type ProfileUpdateFormValues = z.infer<typeof profileUpdateSchema>;
