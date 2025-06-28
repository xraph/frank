import {type ClassValue, clsx} from "clsx";
import {twMerge} from "tailwind-merge";

/**
 * Utility function to merge Tailwind CSS classes with clsx and tailwind-merge
 */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/**
 * Generate a unique ID for components
 */
export function generateId(prefix: string = 'hero-ui'): string {
  return `${prefix}-${Math.random().toString(36).substr(2, 9)}`;
}

/**
 * Debounce function for performance optimization
 */
export function debounce<T extends (...args: any[]) => any>(
    func: T,
    wait: number
): (...args: Parameters<T>) => void {
  let timeout: NodeJS.Timeout;
  return (...args: Parameters<T>) => {
    clearTimeout(timeout);
    timeout = setTimeout(() => func(...args), wait);
  };
}

/**
 * Check if a value is a valid React node
 */
export function isValidElement(value: any): boolean {
  return value !== null && value !== undefined && value !== '';
}

/**
 * Create ripple effect coordinates
 */
export function createRipple(
    event: React.MouseEvent<HTMLElement>,
    element: HTMLElement
): { x: number; y: number; size: number } {
  const rect = element.getBoundingClientRect();
  const x = event.clientX - rect.left;
  const y = event.clientY - rect.top;
  const size = Math.max(rect.width, rect.height);

  return { x, y, size };
}

/**
 * Convert size prop to numeric value
 */
export function getSizeValue(size: 'sm' | 'md' | 'lg' | 'xl'): number {
  const sizeMap = {
    sm: 32,
    md: 40,
    lg: 48,
    xl: 56,
  };
  return sizeMap[size] || sizeMap.md;
}

/**
 * Get contrast color for backgrounds
 */
export function getContrastColor(backgroundColor: string): 'light' | 'dark' {
  // Simple implementation - in a real app, you'd use a proper color contrast calculation
  const darkColors = ['primary', 'destructive', 'success'];
  return darkColors.includes(backgroundColor) ? 'light' : 'dark';
}

/**
 * Format validation error messages
 */
export function formatErrorMessage(error: string | undefined): string | undefined {
  if (!error) return undefined;
  return error.charAt(0).toUpperCase() + error.slice(1);
}