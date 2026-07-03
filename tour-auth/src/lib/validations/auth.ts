import { z } from "zod"

const passwordSchema = z
  .string()
  .min(8, "At least 8 characters")
  .regex(/[A-Z]/, "At least one uppercase letter")
  .regex(/[a-z]/, "At least one lowercase letter")
  .regex(/[0-9]/, "At least one number")
  .regex(/[^A-Za-z0-9]/, "At least one special character")

export const loginSchema = z.object({
  email: z.string().email("Enter a valid email"),
  password: z.string().min(1, "Password is required"),
})

export const registerSchema = z.object({
  email: z.string().email("Enter a valid email"),
  firstName: z.string().min(2, "At least 2 characters").max(50),
  lastName: z.string().min(2, "At least 2 characters").max(50),
  role: z.enum(["MANAGER", "STAFF", "GUIDE"], {
    errorMap: () => ({ message: "Select a role" }),
  }),
})

export const changePasswordSchema = z
  .object({
    currentPassword: z.string().min(1, "Current password required"),
    newPassword: passwordSchema,
    confirmPassword: z.string(),
  })
  .refine((d) => d.newPassword === d.confirmPassword, {
    message: "Passwords don't match",
    path: ["confirmPassword"],
  })
  .refine((d) => d.currentPassword !== d.newPassword, {
    message: "New password must differ from current",
    path: ["newPassword"],
  })

export const otpSchema = z.object({
  otp: z.string().length(6, "Enter the 6-digit code"),
})

export const forgotPasswordSchema = z.object({
  email: z.string().email("Enter a valid email"),
})

export const resetPasswordSchema = z
  .object({
    newPassword: passwordSchema,
    confirmPassword: z.string(),
  })
  .refine((d) => d.newPassword === d.confirmPassword, {
    message: "Passwords don't match",
    path: ["confirmPassword"],
  })

export type LoginFormData         = z.infer<typeof loginSchema>
export type RegisterFormData      = z.infer<typeof registerSchema>
export type ChangePasswordFormData = z.infer<typeof changePasswordSchema>
export type OtpFormData           = z.infer<typeof otpSchema>
export type ForgotPasswordFormData = z.infer<typeof forgotPasswordSchema>
export type ResetPasswordFormData  = z.infer<typeof resetPasswordSchema>
