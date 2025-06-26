import {ReactNode} from 'react';

// Base variants that apply across all components
export type BaseVariant = 'primary' | 'secondary' | 'destructive' | 'success' | 'warning' | 'ghost' | 'link';

// Size variants that apply across all components
export type BaseSize = 'sm' | 'md' | 'lg' | 'xl';

// Shape variants that apply across all components
export type BaseShape = 'square' | 'rounded' | 'circle';

// Radius variants that apply across all components
export type BaseRadius = 'none' | 'sm' | 'md' | 'lg' | 'xl' | 'full';

// Label placement options for input components
export type LabelPlacement = 'inside' | 'outside' | 'outside-left';

// Content positioning for startContent and endContent
export interface ContentProps {
    startContent?: ReactNode;
    endContent?: ReactNode;
}

// Base props that many components share
export interface BaseUIProps extends ContentProps {
    variant?: BaseVariant;
    size?: BaseSize;
    shape?: BaseShape;
    radius?: BaseRadius;
    disabled?: boolean;
    loading?: boolean;
    className?: string;
    children?: ReactNode;
}

// Props specific to components that support labels
export interface LabelableProps {
    label?: string;
    labelPlacement?: LabelPlacement;
    placeholder?: string;
    required?: boolean;
    description?: string;
    errorMessage?: string;
}

// Ripple effect props
export interface RippleProps {
    ripple?: boolean;
    rippleColor?: string;
}

// Button specific props
export interface ButtonProps extends BaseUIProps, RippleProps {
    type?: 'button' | 'submit' | 'reset';
    isIconOnly?: boolean;
    href?: string;
    target?: string;
    rel?: string;
}

// Input component props
export interface InputProps extends BaseUIProps, LabelableProps {
    type?: string;
    value?: string;
    defaultValue?: string;
    onChange?: (value: string) => void;
    onFocus?: () => void;
    onBlur?: () => void;
    name?: string;
    id?: string;
    autoComplete?: string;
    autoFocus?: boolean;
    readOnly?: boolean;
    maxLength?: number;
    minLength?: number;
    pattern?: string;
}

// Select component props
export interface SelectProps extends BaseUIProps, LabelableProps {
    value?: string;
    defaultValue?: string;
    onChange?: (value: string) => void;
    options?: Array<{ value: string; label: string; disabled?: boolean }>;
    multiple?: boolean;
    searchable?: boolean;
    clearable?: boolean;
    name?: string;
    id?: string;
}

// Textarea component props
export interface TextareaProps extends BaseUIProps, LabelableProps {
    value?: string;
    defaultValue?: string;
    onChange?: (value: string) => void;
    onFocus?: () => void;
    onBlur?: () => void;
    name?: string;
    id?: string;
    rows?: number;
    cols?: number;
    resize?: 'none' | 'vertical' | 'horizontal' | 'both';
    autoFocus?: boolean;
    readOnly?: boolean;
    maxLength?: number;
    minLength?: number;
}