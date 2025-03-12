export const variantStyles = {
  default:
    'bg-primary text-primary-foreground shadow-sm hover:bg-primary/90 disabled:bg-primary/50 disabled:text-primary-foreground/50',
  destructive:
    'bg-destructive text-destructive-foreground shadow-xs hover:bg-destructive/90 disabled:bg-destructive/50 disabled:text-destructive-foreground/50',
  outline:
    'border border-input bg-background shadow-xs hover:bg-accent hover:text-accent-foreground disabled:border-input/50 disabled:bg-background/50 disabled:text-accent-foreground/50',
  secondary:
    'bg-secondary text-secondary-foreground shadow-xs hover:bg-secondary/80 disabled:bg-secondary/50 disabled:text-secondary-foreground/50',
  ghost:
    'hover:bg-accent hover:text-accent-foreground disabled:text-accent-foreground/50',
  light:
    'hover:bg-accent hover:text-accent-foreground disabled:text-accent-foreground/50',
  link: 'text-primary underline-offset-4 hover:underline disabled:text-primary/50',
  primary:
    'bg-pyro-bg-brand-solid text-pyro-text-primary-brand hover:bg-pyro-brand-primary/90 disabled:bg-pyro-brand-primary/50 disabled:text-pyro-text-primary-brand/50',
  tertiary:
    'bg-pyro-bg-tertiary text-pyro-bg-tertiary-foreground hover:bg-pyro-bg-tertiary/80 disabled:bg-pyro-bg-tertiary/50 disabled:text-pyro-bg-tertiary-foreground/50',
  quaternary:
    'bg-pyro-bg-quaternary text-pyro-bg-quaternary-foreground hover:bg-pyro-bg-quaternary/80 disabled:bg-pyro-bg-quaternary/50 disabled:text-pyro-bg-quaternary-foreground/50',
  bordered:
    'border border-input bg-background hover:bg-accent hover:text-accent-foreground disabled:border-input/50 disabled:bg-background/50 disabled:text-accent-foreground/50',
}

export const sizeStyles = {
  xs: 'h-6 py-1.5 text-xs group-data-[collapsible=icon]:p-0!',
  sm: 'h-8 text-sm has-[>svg]:px-2.5 group-data-[collapsible=icon]:p-0!',
  default: 'h-9 py-2 text-sm',
  md: 'h-9 py-2 text-sm',
  lg: 'h-10 text-base group-data-[collapsible=icon]:p-0!',
  xl: 'h-11 py-3 text-lg',
  icon: 'h-9 w-9',
}

export const sizeWithPaddingStyles = {
  xs: `${sizeStyles.xs} px-2 has-[>svg]:px-1.5`,
  sm: `${sizeStyles.sm} px-3`,
  default: `${sizeStyles.default} px-4 has-[>svg]:px-3`,
  md: `${sizeStyles.md} px-4 has-[>svg]:px-3`,
  lg: `${sizeStyles.lg} px-6 has-[>svg]:px-4`,
  xl: `${sizeStyles.xl} px-8 py-3 has-[>svg]:px-5`,
  icon: 'h-9 w-9',
}

export const radiusStyles = {
  none: 'rounded-none',
  xs: 'rounded-xs',
  sm: 'rounded-sm',
  md: 'rounded-md',
  lg: 'rounded-lg',
  xl: 'rounded-xl',
  full: 'rounded-full',
}

export const animatedStyles = {
  true: 'transition-transform duration-100 ease-in-out active:scale-95',
  false: '',
}

export const rippleStyles = {
  true: 'relative overflow-hidden',
  false: '',
}

export const isIconOnlyStyles = {
  true: 'aspect-square',
  false: '',
}
