"use client";

import { useEffect, useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Save, KeyRound, Shield } from "lucide-react";
import { toast } from "sonner";
import { PageHeader } from "@/components/layout/page-header";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { authApi } from "@/lib/auth-api";
import { useAuthStore } from "@/store/auth-store";
import type { ApiError, UserProfile } from "@/types/auth";
import { passwordSchema } from "@/lib/validations/auth";

const profileSchema = z.object({
  firstName: z.string().min(1),
  lastName: z.string().min(1),
  phoneNumber: z.string().min(7),
});

const pwSchema = z.object({
  currentPassword: z.string().min(1, "Required"),
  newPassword: passwordSchema,
  confirm: z.string().min(1, "Required"),
}).refine((d) => d.newPassword === d.confirm, {
  message: "Passwords don't match",
  path: ["confirm"],
});

type ProfileForm = z.infer<typeof profileSchema>;
type PwForm = z.infer<typeof pwSchema>;

export default function ProfilePage() {
  const { user, setUser } = useAuthStore();
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [isSavingProfile, setIsSavingProfile] = useState(false);
  const [isChangingPw, setIsChangingPw] = useState(false);

  const profileForm = useForm<ProfileForm>({
    resolver: zodResolver(profileSchema),
    defaultValues: { firstName: "", lastName: "", phoneNumber: "" },
  });

  const pwForm = useForm<PwForm>({
    resolver: zodResolver(pwSchema),
    defaultValues: { currentPassword: "", newPassword: "", confirm: "" },
  });

  useEffect(() => {
    authApi.getProfile()
      .then((p) => {
        setProfile(p);
        profileForm.reset({
          firstName: p.firstName,
          lastName: p.lastName,
          phoneNumber: p.phoneNumber,
        });
      })
      .catch(() => {
        // Fallback to store data
        if (user) {
          profileForm.reset({
            firstName: user.firstName ?? "",
            lastName: user.lastName ?? "",
            phoneNumber: user.phoneNumber ?? "",
          });
        }
      });
  }, []);

  async function saveProfile(values: ProfileForm) {
    setIsSavingProfile(true);
    try {
      const updated = await authApi.updateProfile(values);
      setUser(updated);
      toast.success("Profile updated");
    } catch (err) {
      toast.error((err as ApiError).message || "Couldn't update profile.");
    } finally {
      setIsSavingProfile(false);
    }
  }

  async function changePassword(values: PwForm) {
    setIsChangingPw(true);
    try {
      await authApi.changePassword({
        currentPassword: values.currentPassword,
        newPassword: values.newPassword,
      });
      pwForm.reset();
      toast.success("Password changed successfully");
    } catch (err) {
      toast.error((err as ApiError).message || "Couldn't change password.");
    } finally {
      setIsChangingPw(false);
    }
  }

  const displayUser = profile ?? user;
  const initials = `${displayUser?.firstName?.[0] ?? ""}${displayUser?.lastName?.[0] ?? ""}`.toUpperCase();

  return (
    <div className="space-y-7">
      <PageHeader eyebrow="Account" title="My profile" subtitle="Manage your personal details and security settings." />

      <div className="grid gap-6 lg:grid-cols-3">
        {/* Left: avatar + roles */}
        <Card className="h-fit">
          <CardContent className="flex flex-col items-center p-6 text-center">
            <Avatar className="h-20 w-20">
              <AvatarFallback className="text-2xl font-medium">{initials}</AvatarFallback>
            </Avatar>
            <p className="mt-3 font-display text-lg font-medium">
              {displayUser?.firstName} {displayUser?.lastName}
            </p>
            <p className="text-sm text-muted-foreground">{displayUser?.email}</p>
            <div className="mt-3 flex flex-wrap justify-center gap-1.5">
              {displayUser?.roles?.map((r) => (
                <Badge key={r} variant="secondary" className="text-[10px]">{r}</Badge>
              ))}
            </div>
            <Separator className="my-4" />
            <div className="w-full space-y-2 text-left text-xs">
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">Email verified</span>
                <Badge variant={displayUser?.emailVerified ? "success" : "warning"} className="text-[10px]">
                  {displayUser?.emailVerified ? "Yes" : "No"}
                </Badge>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">Phone verified</span>
                <Badge variant={displayUser?.phoneVerified ? "success" : "warning"} className="text-[10px]">
                  {displayUser?.phoneVerified ? "Yes" : "No"}
                </Badge>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">Account status</span>
                <Badge variant="success" className="text-[10px]">{displayUser?.status}</Badge>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Right: forms */}
        <div className="space-y-5 lg:col-span-2">
          {/* Profile details */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <Shield className="h-4 w-4 text-accent" />
                Personal details
              </CardTitle>
            </CardHeader>
            <CardContent>
              <form onSubmit={profileForm.handleSubmit(saveProfile)} className="space-y-4">
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <Label>First name</Label>
                    <Input {...profileForm.register("firstName")} className="mt-1.5" />
                  </div>
                  <div>
                    <Label>Last name</Label>
                    <Input {...profileForm.register("lastName")} className="mt-1.5" />
                  </div>
                </div>
                <div>
                  <Label>Phone number</Label>
                  <Input {...profileForm.register("phoneNumber")} className="mt-1.5" placeholder="+254…" />
                </div>
                <div className="flex justify-end">
                  <Button type="submit" variant="accent" size="sm" loading={isSavingProfile}>
                    {!isSavingProfile && <Save className="h-3.5 w-3.5" />}
                    Save changes
                  </Button>
                </div>
              </form>
            </CardContent>
          </Card>

          {/* Change password */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <KeyRound className="h-4 w-4 text-accent" />
                Change password
              </CardTitle>
            </CardHeader>
            <CardContent>
              <form onSubmit={pwForm.handleSubmit(changePassword)} className="space-y-4">
                <div>
                  <Label>Current password</Label>
                  <Input type="password" {...pwForm.register("currentPassword")} className="mt-1.5" />
                </div>
                <div>
                  <Label>New password</Label>
                  <Input type="password" {...pwForm.register("newPassword")} className="mt-1.5" />
                  {pwForm.formState.errors.newPassword && (
                    <p className="mt-1 text-xs text-destructive">{pwForm.formState.errors.newPassword.message}</p>
                  )}
                </div>
                <div>
                  <Label>Confirm new password</Label>
                  <Input type="password" {...pwForm.register("confirm")} className="mt-1.5" />
                  {pwForm.formState.errors.confirm && (
                    <p className="mt-1 text-xs text-destructive">{pwForm.formState.errors.confirm.message}</p>
                  )}
                </div>
                <div className="flex justify-end">
                  <Button type="submit" variant="accent" size="sm" loading={isChangingPw}>
                    {!isChangingPw && <KeyRound className="h-3.5 w-3.5" />}
                    Update password
                  </Button>
                </div>
              </form>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
