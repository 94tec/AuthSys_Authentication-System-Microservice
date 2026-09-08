"use client";

import {
    AlertTriangle,
    CheckCircle2,
    Info,
    Loader2,
    XCircle,
} from "lucide-react";
import {
    Toaster as SonnerToaster,
    toast as sonnerToast,
} from "sonner";

type ToastOptions = Parameters<typeof sonnerToast>[1];

export function Toaster() {
    return (
        <SonnerToaster
            position="top-center"
            theme="system"
            richColors
            closeButton
            expand
            visibleToasts={5}
            toastOptions={{
                duration: 5000,

                classNames: {
                    toast: `
                        group
                        relative
                        flex
                        w-full
                        items-start
                        gap-3
                        rounded-2xl
                        border
                        border-border/70
                        bg-background/95
                        px-4
                        py-3.5
                        font-sans
                        text-foreground
                        shadow-xl
                        backdrop-blur-xl
                    `,

                    title: `
                        text-sm
                        font-semibold
                        leading-5
                        text-foreground
                    `,

                    description: `
                        mt-1
                        text-sm
                        leading-5
                        text-muted-foreground
                    `,

                    actionButton: `
                        rounded-lg
                        bg-accent
                        px-3
                        py-1.5
                        text-xs
                        font-semibold
                        text-accent-foreground
                        transition-colors
                        hover:opacity-90
                    `,

                    cancelButton: `
                        rounded-lg
                        bg-muted
                        px-3
                        py-1.5
                        text-xs
                        font-medium
                        text-muted-foreground
                        transition-colors
                        hover:bg-muted/80
                    `,

                    closeButton: `
                        right-2
                        top-2
                        h-7
                        w-7
                        border-0
                        bg-transparent
                        text-muted-foreground
                        opacity-0
                        transition-opacity
                        hover:bg-muted
                        hover:text-foreground
                        group-hover:opacity-100
                    `,

                    success: `
                        border-emerald-500/30
                    `,

                    error: `
                        border-red-500/30
                    `,

                    warning: `
                        border-amber-500/30
                    `,

                    info: `
                        border-blue-500/30
                    `,
                },
            }}
        />
    );
}

/* -------------------------------------------------------------------------- */
/* Icons                                                                      */
/* -------------------------------------------------------------------------- */

const toastIcons = {
    success: (
        <CheckCircle2
            className="mt-0.5 h-5 w-5 shrink-0 text-emerald-500"
            aria-hidden="true"
        />
    ),

    error: (
        <XCircle
            className="mt-0.5 h-5 w-5 shrink-0 text-red-500"
            aria-hidden="true"
        />
    ),

    warning: (
        <AlertTriangle
            className="mt-0.5 h-5 w-5 shrink-0 text-amber-500"
            aria-hidden="true"
        />
    ),

    info: (
        <Info
            className="mt-0.5 h-5 w-5 shrink-0 text-blue-500"
            aria-hidden="true"
        />
    ),

    loading: (
        <Loader2
            className="mt-0.5 h-5 w-5 shrink-0 animate-spin text-accent"
            aria-hidden="true"
        />
    ),
};

/* -------------------------------------------------------------------------- */
/* Application Toast API                                                     */
/* -------------------------------------------------------------------------- */

export const toast = {
    success(
        message: string,
        options?: ToastOptions,
    ) {
        return sonnerToast.success(message, {
            icon: toastIcons.success,
            ...options,
        });
    },

    error(
        message: string,
        options?: ToastOptions,
    ) {
        return sonnerToast.error(message, {
            icon: toastIcons.error,
            ...options,
        });
    },

    warning(
        message: string,
        options?: ToastOptions,
    ) {
        return sonnerToast.warning(message, {
            icon: toastIcons.warning,
            ...options,
        });
    },

    info(
        message: string,
        options?: ToastOptions,
    ) {
        return sonnerToast.info(message, {
            icon: toastIcons.info,
            ...options,
        });
    },

    loading(
        message: string,
        options?: ToastOptions,
    ) {
        return sonnerToast.loading(message, {
            icon: toastIcons.loading,
            ...options,
        });
    },

    promise<T>(
        promise: Promise<T>,
        messages: {
            loading: string;
            success: string;
            error: string;
        },
    ) {
        return sonnerToast.promise(promise, {
            loading: messages.loading,
            success: messages.success,
            error: messages.error,
        });
    },

    dismiss(id?: string | number) {
        sonnerToast.dismiss(id);
    },

    custom: sonnerToast,
};