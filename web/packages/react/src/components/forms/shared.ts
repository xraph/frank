import React from "react";
import {RadiusT, SizeT} from "@/types";


export interface FieldProps<T = any> {
    /**
     * Field name for form handling
     */
    name?: string;

    /**
     * Field label
     */
    label?: string;

    /**
     * Placeholder text
     */
    placeholder?: string;

    /**
     * Field value
     */
    value?: string;

    /**
     * Field value
     */
    defaultValue?: string;

    /**
     * Change handler
     */
    onChange?: (value: T) => void;

    /**
     * Blur handler
     */
    onBlur?: () => void;

    /**
     * Focus handler
     */
    onFocus?: () => void;

    /**
     * Whether field is required
     */
    required?: boolean;

    /**
     * Whether field is disabled
     */
    disabled?: boolean;

    /**
     * Field size
     */
    size?: SizeT;

    /**
     * Field Radius
     */
    radius?: RadiusT;

    /**
     * Custom className
     */
    className?: string;

    /**
     * Auto focus
     */
    autoFocus?: boolean;

    /**
     * Auto complete
     */
    autoComplete?: string;

    /**
     * Custom validation error
     */
    error?: string | string[];

    /**
     * Help text
     */
    description?: string;

    /**
     * Start icon
     */
    startContent?: React.ReactNode;

    /**
     * End content (overrides verification status)
     */
    endContent?: React.ReactNode;
}