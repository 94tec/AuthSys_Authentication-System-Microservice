"use client"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { useRouter } from "next/navigation"
import Link from "next/link"
import { toast } from "sonner"

import { AuthLayout } from "@/components/layout/auth-layout"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent, CardFooter } from "@/components/ui/card"
import { registerSchema, type RegisterFormData } from "@/lib/validations/auth"
import { authApi } from "@/lib/api/auth"
import type { UserRole } from "@/types"

const ROLES: { value: UserRole; label: string }[] = [
  { value: "MANAGER", label: "Manager" },
  { value: "STAFF",   label: "Staff" },
  { value: "GUIDE",   label: "Tour Guide" },
]

export default function RegisterPage() {
  const router = useRouter()
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<RegisterFormData>({ resolver: zodResolver(registerSchema) })

  const onSubmit = async (data: RegisterFormData) => {
    try {
      await authApi.register(data)
      router.push("/register-submitted")
    } catch (err: any) {
      toast.error(err.message ?? "Registration failed. Please try again.")
    }
  }

  return (
    <AuthLayout
      heading="Request access"
      subheading="Submit your details — an admin will review and approve your account"
    >
      <Card>
        <CardContent className="pt-6">
          <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label htmlFor="firstName">First name</Label>
                <Input id="firstName" placeholder="Amara" {...register("firstName")} />
                {errors.firstName && <p className="text-xs text-destructive">{errors.firstName.message}</p>}
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="lastName">Last name</Label>
                <Input id="lastName" placeholder="Osei" {...register("lastName")} />
                {errors.lastName && <p className="text-xs text-destructive">{errors.lastName.message}</p>}
              </div>
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="email">Work email</Label>
              <Input id="email" type="email" placeholder="you@venturetours.com" {...register("email")} />
              {errors.email && <p className="text-xs text-destructive">{errors.email.message}</p>}
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="role">Your role</Label>
              <select
                id="role"
                {...register("role")}
                className="flex h-10 w-full rounded-lg border border-input bg-card px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring transition-all"
              >
                <option value="">Select a role…</option>
                {ROLES.map((r) => (
                  <option key={r.value} value={r.value}>{r.label}</option>
                ))}
              </select>
              {errors.role && <p className="text-xs text-destructive">{errors.role.message}</p>}
            </div>

            <Button type="submit" className="w-full" loading={isSubmitting}>
              Submit request
            </Button>
          </form>
        </CardContent>

        <CardFooter className="justify-center border-t border-border pt-4">
          <p className="text-sm text-muted-foreground">
            Already have an account?{" "}
            <Link href="/login" className="text-[#C9742F] font-medium hover:underline">
              Sign in
            </Link>
          </p>
        </CardFooter>
      </Card>
    </AuthLayout>
  )
}
