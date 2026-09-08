import type { ReactNode } from "react";
import { Sidebar } from "@/components/layout/sidebar";
import { Topbar } from "@/components/layout/topbar";
import {VisitorProvider} from "@/components/landing/visitor-provider";

export default function AdminLayout({ children }: { children: ReactNode }) {
    return (
        <VisitorProvider>
            <div className="flex min-h-screen bg-background">
                <Sidebar />
                <div className="flex flex-1 flex-col">
                    <Topbar />
                    <main className="flex-1 overflow-y-auto p-6 lg:p-8">
                        <div className="mx-auto max-w-7xl">{children}</div>
                    </main>
                </div>
            </div>
        </VisitorProvider>
    );
}