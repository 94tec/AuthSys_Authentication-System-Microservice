// lib/user-api.ts
import { apiClient } from "@/lib/api-client";

export interface StaffUser {
    userId: string;
    fullName: string;
    email: string;
    roles: string[];
}

export const userApi = {
    async listStaff(): Promise<StaffUser[]> {
        const response = await apiClient.get<StaffUser[]>("/admin/users/staff");
        return response.data;
    },
};