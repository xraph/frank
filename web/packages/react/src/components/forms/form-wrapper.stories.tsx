import { Button, Input } from "@/components/ui";
import { action } from "@storybook/addon-actions";
import type { Meta, StoryObj } from "@storybook/react";
import { FormWrapper } from "./form-wrapper";

const meta: Meta<typeof FormWrapper> = {
	title: "Forms/FormWrapper",
	component: FormWrapper,
	parameters: {
		layout: "centered",
		docs: {
			description: {
				component: `
The FormWrapper component provides a consistent container for authentication forms with validation context,
error handling, and theming support. It supports organization customization and various layout options.

## Features
- Form validation context
- Error state management
- Loading states
- Organization theming
- Responsive design
- Accessibility support
        `,
			},
		},
	},
	tags: ["autodocs"],
	argTypes: {
		variant: {
			control: { type: "select" },
			options: ["default", "bordered", "shadow", "flat"],
			description: "Card variant for the form wrapper",
		},
		size: {
			control: { type: "select" },
			options: ["sm", "md", "lg"],
			description: "Size of the form wrapper",
		},
		width: {
			control: { type: "select" },
			options: ["sm", "md", "lg", "xl", "full"],
			description: "Width of the form wrapper",
		},
		title: {
			control: { type: "text" },
			description: "Form title",
		},
		subtitle: {
			control: { type: "text" },
			description: "Form subtitle or description",
		},
		error: {
			control: { type: "text" },
			description: "Global form error message",
		},
		success: {
			control: { type: "text" },
			description: "Success message",
		},
		isSubmitting: {
			control: { type: "boolean" },
			description: "Whether form is currently submitting",
		},
		showCard: {
			control: { type: "boolean" },
			description: "Whether to show the card wrapper",
		},
		centered: {
			control: { type: "boolean" },
			description: "Whether to center the form",
		},
		disableAnimations: {
			control: { type: "boolean" },
			description: "Whether to disable animations",
		},
		onSubmit: {
			action: "onSubmit",
			description: "Form submission handler",
		},
	},
} satisfies Meta<typeof FormWrapper>;

export default meta;
type Story = StoryObj<typeof meta>;

// Sample form content for stories
const SampleFormContent = ({
	isSubmitting = false,
}: { isSubmitting?: boolean }) => (
	<div className="space-y-4">
		<Input
			type="email"
			label="Email"
			placeholder="Enter your email"
			isRequired
			isDisabled={isSubmitting}
		/>
		<Input
			type="password"
			label="Password"
			placeholder="Enter your password"
			isRequired
			isDisabled={isSubmitting}
		/>
		<Button
			type="submit"
			color="primary"
			className="w-full"
			isLoading={isSubmitting}
		>
			{isSubmitting ? "Signing in..." : "Sign In"}
		</Button>
	</div>
);

// Default story
export const Default: Story = {
	args: {
		title: "Sign In",
		subtitle: "Enter your credentials to access your account",
		variant: "shadow",
		size: "md",
		width: "md",
		showCard: true,
		centered: true,
		onSubmit: action("onSubmit"),
		children: <SampleFormContent />,
	},
};

// Sign In Form
export const SignInForm: Story = {
	args: {
		title: "Welcome back",
		subtitle: "Sign in to your account to continue",
		variant: "shadow",
		size: "md",
		width: "md",
		showCard: true,
		centered: true,
		onSubmit: action("onSubmit"),
		children: <SampleFormContent />,
	},
};

// Sign Up Form
export const SignUpForm: Story = {
	args: {
		title: "Create your account",
		subtitle: "Join thousands of users who trust our platform",
		variant: "shadow",
		size: "lg",
		width: "lg",
		showCard: true,
		centered: true,
		onSubmit: action("onSubmit"),
		children: (
			<div className="space-y-4">
				<Input
					type="text"
					label="Full Name"
					placeholder="Enter your full name"
					isRequired
				/>
				<Input
					type="email"
					label="Email"
					placeholder="Enter your email"
					isRequired
				/>
				<Input
					type="password"
					label="Password"
					placeholder="Create a password"
					isRequired
				/>
				<Input
					type="password"
					label="Confirm Password"
					placeholder="Confirm your password"
					isRequired
				/>
				<Button type="submit" color="primary" className="w-full">
					Create Account
				</Button>
			</div>
		),
	},
};

// Loading State
export const LoadingState: Story = {
	args: {
		title: "Signing you in...",
		subtitle: "Please wait while we verify your credentials",
		variant: "shadow",
		size: "md",
		width: "md",
		isSubmitting: true,
		showCard: true,
		centered: true,
		onSubmit: action("onSubmit"),
		children: <SampleFormContent isSubmitting={true} />,
	},
};

// Error State
export const ErrorState: Story = {
	args: {
		title: "Sign In",
		subtitle: "Enter your credentials to access your account",
		error: "Invalid email or password. Please try again.",
		variant: "shadow",
		size: "md",
		width: "md",
		showCard: true,
		centered: true,
		onSubmit: action("onSubmit"),
		children: <SampleFormContent />,
	},
};

// Success State
export const SuccessState: Story = {
	args: {
		title: "Account Created",
		subtitle: "Your account has been successfully created",
		success:
			"Welcome to Frank Auth! Please check your email to verify your account.",
		variant: "shadow",
		size: "md",
		width: "md",
		showCard: true,
		centered: true,
		onSubmit: action("onSubmit"),
		children: (
			<div className="space-y-4">
				<Button color="primary" className="w-full">
					Continue to Dashboard
				</Button>
				<Button variant="light" className="w-full">
					Resend Verification Email
				</Button>
			</div>
		),
	},
};

// Bordered Variant
export const BorderedVariant: Story = {
	args: {
		title: "Secure Login",
		subtitle: "Protected by enterprise-grade security",
		variant: "bordered",
		size: "md",
		width: "md",
		showCard: true,
		centered: true,
		onSubmit: action("onSubmit"),
		children: <SampleFormContent />,
	},
};

// Flat Variant
export const FlatVariant: Story = {
	args: {
		title: "Quick Access",
		subtitle: "Fast and simple authentication",
		variant: "flat",
		size: "md",
		width: "md",
		showCard: true,
		centered: true,
		onSubmit: action("onSubmit"),
		children: <SampleFormContent />,
	},
};

// Small Size
export const SmallSize: Story = {
	args: {
		title: "Sign In",
		variant: "shadow",
		size: "sm",
		width: "sm",
		showCard: true,
		centered: true,
		onSubmit: action("onSubmit"),
		children: (
			<div className="space-y-3">
				<Input type="email" label="Email" size="sm" isRequired />
				<Input type="password" label="Password" size="sm" isRequired />
				<Button type="submit" color="primary" size="sm" className="w-full">
					Sign In
				</Button>
			</div>
		),
	},
};

// Large Size
export const LargeSize: Story = {
	args: {
		title: "Enterprise Portal",
		subtitle: "Access your organization's resources securely",
		variant: "shadow",
		size: "lg",
		width: "lg",
		showCard: true,
		centered: true,
		onSubmit: action("onSubmit"),
		children: (
			<div className="space-y-6">
				<Input
					type="email"
					label="Work Email"
					placeholder="you@company.com"
					size="lg"
					isRequired
				/>
				<Input type="password" label="Password" size="lg" isRequired />
				<Button type="submit" color="primary" size="lg" className="w-full">
					Access Portal
				</Button>
			</div>
		),
	},
};

// Without Card
export const WithoutCard: Story = {
	args: {
		title: "Minimal Form",
		subtitle: "Clean and simple design",
		showCard: false,
		centered: true,
		onSubmit: action("onSubmit"),
		children: <SampleFormContent />,
	},
};

// Full Width
export const FullWidth: Story = {
	args: {
		title: "Full Width Form",
		subtitle: "Spans the entire available width",
		variant: "flat",
		width: "full",
		showCard: true,
		centered: false,
		onSubmit: action("onSubmit"),
		children: <SampleFormContent />,
	},
	parameters: {
		layout: "fullscreen",
	},
};

// With Custom Header and Footer
export const CustomHeaderFooter: Story = {
	args: {
		variant: "shadow",
		size: "md",
		width: "md",
		showCard: true,
		centered: true,
		header: (
			<div className="text-center">
				<div className="w-12 h-12 bg-primary-100 rounded-full flex items-center justify-center mx-auto mb-4">
					<span className="text-primary-600 text-xl">🔐</span>
				</div>
				<h2 className="text-2xl font-bold text-foreground">Secure Access</h2>
				<p className="text-default-500 mt-2">
					Multi-factor authentication required
				</p>
			</div>
		),
		footer: (
			<div className="text-center pt-4 border-t border-divider">
				<p className="text-sm text-default-500">
					Need help?{" "}
					<a href="#" className="text-primary-600 hover:underline">
						Contact Support
					</a>
				</p>
			</div>
		),
		onSubmit: action("onSubmit"),
		children: <SampleFormContent />,
	},
};

// With Organization Logo
export const WithOrganizationLogo: Story = {
	args: {
		title: "Welcome to Acme Corp",
		subtitle: "Sign in with your work account",
		variant: "shadow",
		size: "md",
		width: "md",
		logo: "https://via.placeholder.com/150x50/3b82f6/ffffff?text=ACME",
		showCard: true,
		centered: true,
		onSubmit: action("onSubmit"),
		children: <SampleFormContent />,
	},
};
