// lib/customer-api.ts

import { apiClient } from "@/lib/api-client";
import type { Customer } from "@/app/(admin)/customers/page";

export interface CustomerPageResponse {
    content: Customer[];
    totalElements: number;
    totalPages: number;
    number: number;
    size: number;
    numberOfElements: number;
    first: boolean;
    last: boolean;
    empty: boolean;
}

export interface CustomerCountResponse {
    success: boolean;
    message: string;
    data: number;
}

export const customerApi = {
    /**
     * Get all customers.
     *
     * Backend:
     * GET /api/customers/admin/all?page=0&size=20
     *
     * Requires:
     * ADMIN or SUPER_ADMIN
     */
    async listCustomers(
        page = 0,
        size = 20
    ): Promise<CustomerPageResponse> {
        const response = await apiClient.get<CustomerPageResponse>(
            "/customers/admin/all",
            {
                params: {
                    page,
                    size,
                },
            }
        );

        return response.data;
    },

    /**
     * Search customers by name or email.
     *
     * Backend:
     * GET /api/customers/admin/search?q=john&page=0&size=20
     *
     * Requires:
     * MANAGER, ADMIN or SUPER_ADMIN
     */
    async searchCustomers(
        query: string,
        page = 0,
        size = 20
    ): Promise<CustomerPageResponse> {
        const response = await apiClient.get<CustomerPageResponse>(
            "/customers/admin/search",
            {
                params: {
                    q: query.trim(),
                    page,
                    size,
                },
            }
        );

        return response.data;
    },

    /**
     * Get a single customer profile.
     *
     * Backend:
     * GET /api/customers/admin/{profileId}
     *
     * Requires:
     * MANAGER, ADMIN or SUPER_ADMIN
     */
    async getCustomer(
        profileId: string
    ): Promise<Customer> {
        const response = await apiClient.get<Customer>(
            `/customers/admin/${profileId}`
        );

        return response.data;
    },

    /**
     * Get total registered customer count.
     *
     * Backend:
     * GET /api/customers/admin/stats/count
     *
     * Response:
     * {
     *   success: true,
     *   message: "Total customers",
     *   data: 123
     * }
     */
    async countCustomers(): Promise<number> {
        const response =
            await apiClient.get<CustomerCountResponse>(
                "/customers/admin/stats/count"
            );

        return response.data.data;
    },
};