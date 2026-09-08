// types/nav.ts
export interface NavChild {
    href: string;
    label: string;
}

export interface NavGroup {
    /** Section header shown inside the dropdown, e.g. "By Country" */
    label: string;
    items: NavChild[];
}

export interface NavItem {
    href: string;
    label: string;
    /** Use for dropdowns that mix independent filter axes (safaris, destinations). */
    groups?: NavGroup[];
    /** Use for simple flat dropdowns (hotels, experiences — for now). */
    children?: NavChild[];
}