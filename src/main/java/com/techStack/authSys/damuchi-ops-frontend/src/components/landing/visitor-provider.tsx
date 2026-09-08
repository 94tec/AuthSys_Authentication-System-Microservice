"use client";

import { createContext, useContext } from "react";
import { useVisitor, type Visitor } from "@/hooks/use-visitor";

const VisitorContext = createContext<Visitor>({ status: "loading", user: null });

export function VisitorProvider({ children }: { children: React.ReactNode }) {
    const visitor = useVisitor();
    return (
        <VisitorContext.Provider value={visitor}>{children}</VisitorContext.Provider>
    );
}

export function useVisitorContext() {
    return useContext(VisitorContext);
}