import { cn } from "@/lib/utils";
import { type VariantProps, cva } from "class-variance-authority";
import type React from "react";
import { forwardRef, memo } from "react";

/**
 * A flexible box/block component with extensive styling options
 * Serves as a foundational layout primitive for building consistent UIs
 */
const boxVariants = cva("", {
	variants: {
		// Layout
		display: {
			block: "block",
			inline: "inline",
			flex: "flex",
			inlineFlex: "inline-flex",
			grid: "grid",
			inlineGrid: "inline-grid",
			hidden: "hidden",
		},
		position: {
			static: "static",
			relative: "relative",
			absolute: "absolute",
			fixed: "fixed",
			sticky: "sticky",
		},
		// Flex & Grid
		direction: {
			row: "flex-row",
			column: "flex-col",
			rowReverse: "flex-row-reverse",
			columnReverse: "flex-col-reverse",
		},
		align: {
			start: "items-start",
			center: "items-center",
			end: "items-end",
			baseline: "items-baseline",
			stretch: "items-stretch",
		},
		justify: {
			start: "justify-start",
			center: "justify-center",
			end: "justify-end",
			between: "justify-between",
			around: "justify-around",
			evenly: "justify-evenly",
		},
		wrap: {
			wrap: "flex-wrap",
			nowrap: "flex-nowrap",
			wrapReverse: "flex-wrap-reverse",
		},
		gap: {
			0: "gap-0",
			px: "gap-px",
			0.5: "gap-0.5",
			1: "gap-1",
			1.5: "gap-1.5",
			2: "gap-2",
			2.5: "gap-2.5",
			3: "gap-3",
			3.5: "gap-3.5",
			4: "gap-4",
			5: "gap-5",
			6: "gap-6",
			7: "gap-7",
			8: "gap-8",
			9: "gap-9",
			10: "gap-10",
			11: "gap-11",
			12: "gap-12",
			14: "gap-14",
			16: "gap-16",
			20: "gap-20",
			24: "gap-24",
			28: "gap-28",
			32: "gap-32",
			36: "gap-36",
			40: "gap-40",
			44: "gap-44",
			48: "gap-48",
			52: "gap-52",
			56: "gap-56",
			60: "gap-60",
			64: "gap-64",
			72: "gap-72",
			80: "gap-80",
			96: "gap-96",
			xs: "gap-2",
			sm: "gap-4",
			md: "gap-6",
			lg: "gap-8",
			xl: "gap-10",
			"2xl": "gap-12",
			"3xl": "gap-16",
			"4xl": "gap-20",
			"5xl": "gap-24",
			"6xl": "gap-32",
			"7xl": "gap-40",
		},
		// Padding
		p: {
			0: "p-0",
			px: "p-px",
			0.5: "p-0.5",
			1: "p-1",
			1.5: "p-1.5",
			2: "p-2",
			2.5: "p-2.5",
			3: "p-3",
			3.5: "p-3.5",
			4: "p-4",
			5: "p-5",
			6: "p-6",
			7: "p-7",
			8: "p-8",
			9: "p-9",
			10: "p-10",
			11: "p-11",
			12: "p-12",
			14: "p-14",
			16: "p-16",
			20: "p-20",
			24: "p-24",
			28: "p-28",
			32: "p-32",
			36: "p-36",
			40: "p-40",
			44: "p-44",
			48: "p-48",
			52: "p-52",
			56: "p-56",
			60: "p-60",
			64: "p-64",
			72: "p-72",
			80: "p-80",
			96: "p-96",
			xs: "p-2",
			sm: "p-4",
			md: "p-6",
			lg: "p-8",
			xl: "p-10",
			"2xl": "p-12",
			"3xl": "p-16",
			"4xl": "p-20",
			"5xl": "p-24",
			"6xl": "p-32",
			"7xl": "p-40",
		},
		px: {
			0: "px-0",
			px: "px-px",
			0.5: "px-0.5",
			1: "px-1",
			1.5: "px-1.5",
			2: "px-2",
			2.5: "px-2.5",
			3: "px-3",
			3.5: "px-3.5",
			4: "px-4",
			5: "px-5",
			6: "px-6",
			7: "px-7",
			8: "px-8",
			9: "px-9",
			10: "px-10",
			11: "px-11",
			12: "px-12",
			14: "px-14",
			16: "px-16",
			20: "px-20",
			24: "px-24",
			28: "px-28",
			32: "px-32",
			36: "px-36",
			40: "px-40",
			44: "px-44",
			48: "px-48",
			52: "px-52",
			56: "px-56",
			60: "px-60",
			64: "px-64",
			72: "px-72",
			80: "px-80",
			96: "px-96",
			xs: "px-2",
			sm: "px-4",
			md: "px-6",
			lg: "px-8",
			xl: "px-10",
			"2xl": "px-12",
			"3xl": "px-16",
			"4xl": "px-20",
			"5xl": "px-24",
			"6xl": "px-32",
			"7xl": "px-40",
		},
		py: {
			0: "py-0",
			px: "py-px",
			0.5: "py-0.5",
			1: "py-1",
			1.5: "py-1.5",
			2: "py-2",
			2.5: "py-2.5",
			3: "py-3",
			3.5: "py-3.5",
			4: "py-4",
			5: "py-5",
			6: "py-6",
			7: "py-7",
			8: "py-8",
			9: "py-9",
			10: "py-10",
			11: "py-11",
			12: "py-12",
			14: "py-14",
			16: "py-16",
			20: "py-20",
			24: "py-24",
			28: "py-28",
			32: "py-32",
			36: "py-36",
			40: "py-40",
			44: "py-44",
			48: "py-48",
			52: "py-52",
			56: "py-56",
			60: "py-60",
			64: "py-64",
			72: "py-72",
			80: "py-80",
			96: "py-96",
			xs: "py-2",
			sm: "py-4",
			md: "py-6",
			lg: "py-8",
			xl: "py-10",
			"2xl": "py-12",
			"3xl": "py-16",
			"4xl": "py-20",
			"5xl": "py-24",
			"6xl": "py-32",
			"7xl": "py-40",
		},
		pt: {
			0: "pt-0",
			px: "pt-px",
			0.5: "pt-0.5",
			1: "pt-1",
			1.5: "pt-1.5",
			2: "pt-2",
			2.5: "pt-2.5",
			3: "pt-3",
			3.5: "pt-3.5",
			4: "pt-4",
			5: "pt-5",
			6: "pt-6",
			7: "pt-7",
			8: "pt-8",
			9: "pt-9",
			10: "pt-10",
			11: "pt-11",
			12: "pt-12",
			14: "pt-14",
			16: "pt-16",
			20: "pt-20",
			24: "pt-24",
			28: "pt-28",
			32: "pt-32",
			36: "pt-36",
			40: "pt-40",
			44: "pt-44",
			48: "pt-48",
			52: "pt-52",
			56: "pt-56",
			60: "pt-60",
			64: "pt-64",
			72: "pt-72",
			80: "pt-80",
			96: "pt-96",
			xs: "pt-2",
			sm: "pt-4",
			md: "pt-6",
			lg: "pt-8",
			xl: "pt-10",
			"2xl": "pt-12",
			"3xl": "pt-16",
			"4xl": "pt-20",
			"5xl": "pt-24",
			"6xl": "pt-32",
			"7xl": "pt-40",
		},
		pb: {
			0: "pb-0",
			px: "pb-px",
			0.5: "pb-0.5",
			1: "pb-1",
			1.5: "pb-1.5",
			2: "pb-2",
			2.5: "pb-2.5",
			3: "pb-3",
			3.5: "pb-3.5",
			4: "pb-4",
			5: "pb-5",
			6: "pb-6",
			7: "pb-7",
			8: "pb-8",
			9: "pb-9",
			10: "pb-10",
			11: "pb-11",
			12: "pb-12",
			14: "pb-14",
			16: "pb-16",
			20: "pb-20",
			24: "pb-24",
			28: "pb-28",
			32: "pb-32",
			36: "pb-36",
			40: "pb-40",
			44: "pb-44",
			48: "pb-48",
			52: "pb-52",
			56: "pb-56",
			60: "pb-60",
			64: "pb-64",
			72: "pb-72",
			80: "pb-80",
			96: "pb-96",
			xs: "pb-2",
			sm: "pb-4",
			md: "pb-6",
			lg: "pb-8",
			xl: "pb-10",
			"2xl": "pb-12",
			"3xl": "pb-16",
			"4xl": "pb-20",
			"5xl": "pb-24",
			"6xl": "pb-32",
			"7xl": "pb-40",
		},
		pl: {
			0: "pl-0",
			px: "pl-px",
			0.5: "pl-0.5",
			1: "pl-1",
			1.5: "pl-1.5",
			2: "pl-2",
			2.5: "pl-2.5",
			3: "pl-3",
			3.5: "pl-3.5",
			4: "pl-4",
			5: "pl-5",
			6: "pl-6",
			7: "pl-7",
			8: "pl-8",
			9: "pl-9",
			10: "pl-10",
			11: "pl-11",
			12: "pl-12",
			14: "pl-14",
			16: "pl-16",
			20: "pl-20",
			24: "pl-24",
			28: "pl-28",
			32: "pl-32",
			36: "pl-36",
			40: "pl-40",
			44: "pl-44",
			48: "pl-48",
			52: "pl-52",
			56: "pl-56",
			60: "pl-60",
			64: "pl-64",
			72: "pl-72",
			80: "pl-80",
			96: "pl-96",
			xs: "pl-2",
			sm: "pl-4",
			md: "pl-6",
			lg: "pl-8",
			xl: "pl-10",
			"2xl": "pl-12",
			"3xl": "pl-16",
			"4xl": "pl-20",
			"5xl": "pl-24",
			"6xl": "pl-32",
			"7xl": "pl-40",
		},
		pr: {
			0: "pr-0",
			px: "pr-px",
			0.5: "pr-0.5",
			1: "pr-1",
			1.5: "pr-1.5",
			2: "pr-2",
			2.5: "pr-2.5",
			3: "pr-3",
			3.5: "pr-3.5",
			4: "pr-4",
			5: "pr-5",
			6: "pr-6",
			7: "pr-7",
			8: "pr-8",
			9: "pr-9",
			10: "pr-10",
			11: "pr-11",
			12: "pr-12",
			14: "pr-14",
			16: "pr-16",
			20: "pr-20",
			24: "pr-24",
			28: "pr-28",
			32: "pr-32",
			36: "pr-36",
			40: "pr-40",
			44: "pr-44",
			48: "pr-48",
			52: "pr-52",
			56: "pr-56",
			60: "pr-60",
			64: "pr-64",
			72: "pr-72",
			80: "pr-80",
			96: "pr-96",
			xs: "pr-2",
			sm: "pr-4",
			md: "pr-6",
			lg: "pr-8",
			xl: "pr-10",
			"2xl": "pr-12",
			"3xl": "pr-16",
			"4xl": "pr-20",
			"5xl": "pr-24",
			"6xl": "pr-32",
			"7xl": "pr-40",
		},
		// Margin
		m: {
			0: "m-0",
			px: "m-px",
			0.5: "m-0.5",
			1: "m-1",
			1.5: "m-1.5",
			2: "m-2",
			2.5: "m-2.5",
			3: "m-3",
			3.5: "m-3.5",
			4: "m-4",
			5: "m-5",
			6: "m-6",
			7: "m-7",
			8: "m-8",
			9: "m-9",
			10: "m-10",
			11: "m-11",
			12: "m-12",
			14: "m-14",
			16: "m-16",
			20: "m-20",
			24: "m-24",
			28: "m-28",
			32: "m-32",
			36: "m-36",
			40: "m-40",
			44: "m-44",
			48: "m-48",
			52: "m-52",
			56: "m-56",
			60: "m-60",
			64: "m-64",
			72: "m-72",
			80: "m-80",
			96: "m-96",
			auto: "m-auto",
			xs: "m-2",
			sm: "m-4",
			md: "m-6",
			lg: "m-8",
			xl: "m-10",
			"2xl": "m-12",
			"3xl": "m-16",
			"4xl": "m-20",
			"5xl": "m-24",
			"6xl": "m-32",
			"7xl": "m-40",
		},
		mx: {
			0: "mx-0",
			px: "mx-px",
			0.5: "mx-0.5",
			1: "mx-1",
			1.5: "mx-1.5",
			2: "mx-2",
			2.5: "mx-2.5",
			3: "mx-3",
			3.5: "mx-3.5",
			4: "mx-4",
			5: "mx-5",
			6: "mx-6",
			7: "mx-7",
			8: "mx-8",
			9: "mx-9",
			10: "mx-10",
			11: "mx-11",
			12: "mx-12",
			14: "mx-14",
			16: "mx-16",
			20: "mx-20",
			24: "mx-24",
			28: "mx-28",
			32: "mx-32",
			36: "mx-36",
			40: "mx-40",
			44: "mx-44",
			48: "mx-48",
			52: "mx-52",
			56: "mx-56",
			60: "mx-60",
			64: "mx-64",
			72: "mx-72",
			80: "mx-80",
			96: "mx-96",
			auto: "mx-auto",
			xs: "mx-2",
			sm: "mx-4",
			md: "mx-6",
			lg: "mx-8",
			xl: "mx-10",
			"2xl": "mx-12",
			"3xl": "mx-16",
			"4xl": "mx-20",
			"5xl": "mx-24",
			"6xl": "mx-32",
			"7xl": "mx-40",
		},
		my: {
			0: "my-0",
			px: "my-px",
			0.5: "my-0.5",
			1: "my-1",
			1.5: "my-1.5",
			2: "my-2",
			2.5: "my-2.5",
			3: "my-3",
			3.5: "my-3.5",
			4: "my-4",
			5: "my-5",
			6: "my-6",
			7: "my-7",
			8: "my-8",
			9: "my-9",
			10: "my-10",
			11: "my-11",
			12: "my-12",
			14: "my-14",
			16: "my-16",
			20: "my-20",
			24: "my-24",
			28: "my-28",
			32: "my-32",
			36: "my-36",
			40: "my-40",
			44: "my-44",
			48: "my-48",
			52: "my-52",
			56: "my-56",
			60: "my-60",
			64: "my-64",
			72: "my-72",
			80: "my-80",
			96: "my-96",
			auto: "my-auto",
			xs: "my-2",
			sm: "my-4",
			md: "my-6",
			lg: "my-8",
			xl: "my-10",
			"2xl": "my-12",
			"3xl": "my-16",
			"4xl": "my-20",
			"5xl": "my-24",
			"6xl": "my-32",
			"7xl": "my-40",
		},
		mt: {
			0: "mt-0",
			px: "mt-px",
			0.5: "mt-0.5",
			1: "mt-1",
			1.5: "mt-1.5",
			2: "mt-2",
			2.5: "mt-2.5",
			3: "mt-3",
			3.5: "mt-3.5",
			4: "mt-4",
			5: "mt-5",
			6: "mt-6",
			7: "mt-7",
			8: "mt-8",
			9: "mt-9",
			10: "mt-10",
			11: "mt-11",
			12: "mt-12",
			14: "mt-14",
			16: "mt-16",
			20: "mt-20",
			24: "mt-24",
			28: "mt-28",
			32: "mt-32",
			36: "mt-36",
			40: "mt-40",
			44: "mt-44",
			48: "mt-48",
			52: "mt-52",
			56: "mt-56",
			60: "mt-60",
			64: "mt-64",
			72: "mt-72",
			80: "mt-80",
			96: "mt-96",
			auto: "mt-auto",
			xs: "mt-2",
			sm: "mt-4",
			md: "mt-6",
			lg: "mt-8",
			xl: "mt-10",
			"2xl": "mt-12",
			"3xl": "mt-16",
			"4xl": "mt-20",
			"5xl": "mt-24",
			"6xl": "mt-32",
			"7xl": "mt-40",
		},
		mb: {
			0: "mb-0",
			px: "mb-px",
			0.5: "mb-0.5",
			1: "mb-1",
			1.5: "mb-1.5",
			2: "mb-2",
			2.5: "mb-2.5",
			3: "mb-3",
			3.5: "mb-3.5",
			4: "mb-4",
			5: "mb-5",
			6: "mb-6",
			7: "mb-7",
			8: "mb-8",
			9: "mb-9",
			10: "mb-10",
			11: "mb-11",
			12: "mb-12",
			14: "mb-14",
			16: "mb-16",
			20: "mb-20",
			24: "mb-24",
			28: "mb-28",
			32: "mb-32",
			36: "mb-36",
			40: "mb-40",
			44: "mb-44",
			48: "mb-48",
			52: "mb-52",
			56: "mb-56",
			60: "mb-60",
			64: "mb-64",
			72: "mb-72",
			80: "mb-80",
			96: "mb-96",
			auto: "mb-auto",
			xs: "mb-2",
			sm: "mb-4",
			md: "mb-6",
			lg: "mb-8",
			xl: "mb-10",
			"2xl": "mb-12",
			"3xl": "mb-16",
			"4xl": "mb-20",
			"5xl": "mb-24",
			"6xl": "mb-32",
			"7xl": "mb-40",
		},
		mr: {
			0: "mr-0",
			px: "mr-px",
			0.5: "mr-0.5",
			1: "mr-1",
			1.5: "mr-1.5",
			2: "mr-2",
			2.5: "mr-2.5",
			3: "mr-3",
			3.5: "mr-3.5",
			4: "mr-4",
			5: "mr-5",
			6: "mr-6",
			7: "mr-7",
			8: "mr-8",
			9: "mr-9",
			10: "mr-10",
			11: "mr-11",
			12: "mr-12",
			14: "mr-14",
			16: "mr-16",
			20: "mr-20",
			24: "mr-24",
			28: "mr-28",
			32: "mr-32",
			36: "mr-36",
			40: "mr-40",
			44: "mr-44",
			48: "mr-48",
			52: "mr-52",
			56: "mr-56",
			60: "mr-60",
			64: "mr-64",
			72: "mr-72",
			80: "mr-80",
			96: "mr-96",
			auto: "mr-auto",
			xs: "mr-2",
			sm: "mr-4",
			md: "mr-6",
			lg: "mr-8",
			xl: "mr-10",
			"2xl": "mr-12",
			"3xl": "mr-16",
			"4xl": "mr-20",
			"5xl": "mr-24",
			"6xl": "mr-32",
			"7xl": "mr-40",
		},
		ml: {
			0: "ml-0",
			px: "ml-px",
			0.5: "ml-0.5",
			1: "ml-1",
			1.5: "ml-1.5",
			2: "ml-2",
			2.5: "ml-2.5",
			3: "ml-3",
			3.5: "ml-3.5",
			4: "ml-4",
			5: "ml-5",
			6: "ml-6",
			7: "ml-7",
			8: "ml-8",
			9: "ml-9",
			10: "ml-10",
			11: "ml-11",
			12: "ml-12",
			14: "ml-14",
			16: "ml-16",
			20: "ml-20",
			24: "ml-24",
			28: "ml-28",
			32: "ml-32",
			36: "ml-36",
			40: "ml-40",
			44: "ml-44",
			48: "ml-48",
			52: "ml-52",
			56: "ml-56",
			60: "ml-60",
			64: "ml-64",
			72: "ml-72",
			80: "ml-80",
			96: "ml-96",
			auto: "ml-auto",
			xs: "ml-2",
			sm: "ml-4",
			md: "ml-6",
			lg: "ml-8",
			xl: "ml-10",
			"2xl": "ml-12",
			"3xl": "ml-16",
			"4xl": "ml-20",
			"5xl": "ml-24",
			"6xl": "ml-32",
			"7xl": "ml-40",
		},
		// Width and Height
		width: {
			auto: "w-auto",
			full: "w-full",
			screen: "w-screen",
			min: "w-min",
			max: "w-max",
			fit: "w-fit",
			xs: "w-4",
			sm: "w-8",
			md: "w-12",
			lg: "w-16",
			xl: "w-20",
			"2xl": "w-24",
			"3xl": "w-32",
			"4xl": "w-40",
			"5xl": "w-48",
			"6xl": "w-64",
			"7xl": "w-80",
			"1/2": "w-1/2",
			"1/3": "w-1/3",
			"2/3": "w-2/3",
			"1/4": "w-1/4",
			"3/4": "w-3/4",
			"1/5": "w-1/5",
			"2/5": "w-2/5",
			"3/5": "w-3/5",
			"4/5": "w-4/5",
			"1/6": "w-1/6",
			"5/6": "w-5/6",
			"1/12": "w-1/12",
			"5/12": "w-5/12",
			"7/12": "w-7/12",
			"11/12": "w-11/12",
			1: "w-1",
			2: "w-2",
			4: "w-4",
			8: "w-8",
			12: "w-12",
			16: "w-16",
			20: "w-20",
			24: "w-24",
			28: "w-28",
			32: "w-32",
			36: "w-36",
			40: "w-40",
			48: "w-48",
			56: "w-56",
			64: "w-64",
			72: "w-72",
			80: "w-80",
			96: "w-96",
		},
		height: {
			auto: "h-auto",
			full: "h-full",
			screen: "h-screen",
			min: "h-min",
			max: "h-max",
			fit: "h-fit",
			xs: "h-4",
			sm: "h-8",
			md: "h-12",
			lg: "h-16",
			xl: "h-20",
			"2xl": "h-24",
			"3xl": "h-32",
			"4xl": "h-40",
			"5xl": "h-48",
			"6xl": "h-64",
			"7xl": "h-80",
			"1/2": "h-1/2",
			"1/3": "h-1/3",
			"2/3": "h-2/3",
			"1/4": "h-1/4",
			"3/4": "h-3/4",
			"1/5": "h-1/5",
			"2/5": "h-2/5",
			"3/5": "h-3/5",
			"4/5": "h-4/5",
			"1/6": "h-1/6",
			1: "h-1",
			2: "h-2",
			4: "h-4",
			8: "h-8",
			12: "h-12",
			16: "h-16",
			20: "h-20",
			24: "h-24",
			28: "h-28",
			32: "h-32",
			36: "h-36",
			40: "h-40",
			48: "h-48",
			56: "h-56",
			64: "h-64",
			72: "h-72",
			80: "h-80",
			96: "h-96",
		},
		// Other visual properties
		maxWidth: {
			none: "max-w-none",
			xs: "max-w-xs",
			sm: "max-w-sm",
			md: "max-w-md",
			lg: "max-w-lg",
			xl: "max-w-xl",
			"2xl": "max-w-2xl",
			"3xl": "max-w-3xl",
			"4xl": "max-w-4xl",
			"5xl": "max-w-5xl",
			"6xl": "max-w-6xl",
			"7xl": "max-w-7xl",
			full: "max-w-full",
			min: "max-w-min",
			max: "max-w-max",
			fit: "max-w-fit",
			prose: "max-w-prose",
			"screen-sm": "max-w-screen-sm",
			"screen-md": "max-w-screen-md",
			"screen-lg": "max-w-screen-lg",
			"screen-xl": "max-w-screen-xl",
			"screen-2xl": "max-w-screen-2xl",
		},
		minWidth: {
			0: "min-w-0",
			full: "min-w-full",
			min: "min-w-min",
			max: "min-w-max",
			fit: "min-w-fit",
			xs: "min-w-[20rem]",
			sm: "min-w-[24rem]",
			md: "min-w-[28rem]",
			lg: "min-w-[32rem]",
			xl: "min-w-[36rem]",
			"2xl": "min-w-[42rem]",
			"3xl": "min-w-[48rem]",
			"4xl": "min-w-[56rem]",
			"5xl": "min-w-[64rem]",
			"6xl": "min-w-[72rem]",
			"7xl": "min-w-[80rem]",
		},
		maxHeight: {
			none: "max-h-none",
			xs: "max-h-[20rem]",
			sm: "max-h-[24rem]",
			md: "max-h-[28rem]",
			lg: "max-h-[32rem]",
			xl: "max-h-[36rem]",
			"2xl": "max-h-[42rem]",
			"3xl": "max-h-[48rem]",
			"4xl": "max-h-[56rem]",
			"5xl": "max-h-[64rem]",
			"6xl": "max-h-[72rem]",
			"7xl": "max-h-[80rem]",
			full: "max-h-full",
			screen: "max-h-screen",
		},
		minHeight: {
			0: "min-h-0",
			full: "min-h-full",
			screen: "min-h-screen",
			min: "min-h-min",
			max: "min-h-max",
			fit: "min-h-fit",
			xs: "min-h-[20rem]",
			sm: "min-h-[24rem]",
			md: "min-h-[28rem]",
			lg: "min-h-[32rem]",
			xl: "min-h-[36rem]",
			"2xl": "min-h-[42rem]",
			"3xl": "min-h-[48rem]",
			"4xl": "min-h-[56rem]",
			"5xl": "min-h-[64rem]",
			"6xl": "min-h-[72rem]",
			"7xl": "min-h-[80rem]",
		},
		// Visual styling
		bg: {
			transparent: "bg-transparent",
			current: "bg-current",
			background: "bg-background",
			foreground: "bg-foreground",
			primary: "bg-primary",
			"primary-foreground": "bg-primary-foreground",
			secondary: "bg-secondary",
			"secondary-foreground": "bg-secondary-foreground",
			muted: "bg-muted",
			"muted-foreground": "bg-muted-foreground",
			accent: "bg-accent",
			"accent-foreground": "bg-accent-foreground",
			destructive: "bg-destructive",
			"destructive-foreground": "bg-destructive-foreground",
			success: "bg-green-500",
			warning: "bg-amber-500",
			info: "bg-blue-500",
		},
		border: {
			none: "border-0",
			default: "border",
			2: "border-2",
			4: "border-4",
			8: "border-8",
		},
		borderColor: {
			transparent: "border-transparent",
			current: "border-current",
			border: "border-border",
			input: "border-input",
			primary: "border-primary",
			secondary: "border-secondary",
			muted: "border-muted",
			accent: "border-accent",
			destructive: "border-destructive",
			success: "border-green-500",
			warning: "border-amber-500",
			info: "border-blue-500",
		},
		rounded: {
			none: "rounded-none",
			sm: "rounded-sm",
			default: "rounded",
			md: "rounded-md",
			lg: "rounded-lg",
			xl: "rounded-xl",
			"2xl": "rounded-2xl",
			"3xl": "rounded-3xl",
			full: "rounded-full",
		},
		shadow: {
			none: "shadow-none",
			sm: "shadow-sm",
			default: "shadow",
			md: "shadow-md",
			lg: "shadow-lg",
			xl: "shadow-xl",
			"2xl": "shadow-2xl",
			inner: "shadow-inner",
		},
		// Other utilities
		overflow: {
			auto: "overflow-auto",
			hidden: "overflow-hidden",
			visible: "overflow-visible",
			scroll: "overflow-scroll",
		},
		zIndex: {
			0: "z-0",
			10: "z-10",
			20: "z-20",
			30: "z-30",
			40: "z-40",
			50: "z-50",
			auto: "z-auto",
		},
		opacity: {
			0: "opacity-0",
			25: "opacity-25",
			50: "opacity-50",
			75: "opacity-75",
			100: "opacity-100",
		},
	},
	defaultVariants: {
		display: "block",
	},
	compoundVariants: [
		// Apply flex properties only when display is flex or inline-flex
		{
			display: ["flex", "inlineFlex"],
			direction: "row",
			className: "flex-row",
		},
		{
			display: ["flex", "inlineFlex"],
			wrap: "wrap",
			className: "flex-wrap",
		},
		// Apply grid properties only when display is grid or inline-grid
		{
			display: ["grid", "inlineGrid"],
			className: "grid",
		},
	],
});

// Define responsive value type that allows both direct values and responsive objects
export type ResponsiveValue<T> =
	| T
	| {
			base?: T;
			sm?: T;
			md?: T;
			lg?: T;
			xl?: T;
			"2xl"?: T;
	  };

// Box props interface with proper responsive handling
export interface BoxProps extends React.HTMLAttributes<HTMLDivElement> {
	as?: React.ElementType;
	id?: string;
	role?: string;
	animate?: boolean;
	hoverStyles?: string;
	focusStyles?: string;
	activeStyles?: string;

	// Layout
	display?: ResponsiveValue<VariantProps<typeof boxVariants>["display"]>;
	position?: ResponsiveValue<VariantProps<typeof boxVariants>["position"]>;

	// Flex & Grid
	direction?: ResponsiveValue<VariantProps<typeof boxVariants>["direction"]>;
	align?: ResponsiveValue<VariantProps<typeof boxVariants>["align"]>;
	justify?: ResponsiveValue<VariantProps<typeof boxVariants>["justify"]>;
	wrap?: ResponsiveValue<VariantProps<typeof boxVariants>["wrap"]>;
	gap?: ResponsiveValue<VariantProps<typeof boxVariants>["gap"]>;

	// Padding
	p?: ResponsiveValue<VariantProps<typeof boxVariants>["p"]>;
	px?: ResponsiveValue<VariantProps<typeof boxVariants>["px"]>;
	py?: ResponsiveValue<VariantProps<typeof boxVariants>["py"]>;
	pt?: ResponsiveValue<VariantProps<typeof boxVariants>["pt"]>;
	pb?: ResponsiveValue<VariantProps<typeof boxVariants>["pb"]>;
	pr?: ResponsiveValue<VariantProps<typeof boxVariants>["pr"]>;
	pl?: ResponsiveValue<VariantProps<typeof boxVariants>["pl"]>;

	// Margin
	m?: ResponsiveValue<VariantProps<typeof boxVariants>["m"]>;
	mx?: ResponsiveValue<VariantProps<typeof boxVariants>["mx"]>;
	my?: ResponsiveValue<VariantProps<typeof boxVariants>["my"]>;
	mt?: ResponsiveValue<VariantProps<typeof boxVariants>["mt"]>;
	mb?: ResponsiveValue<VariantProps<typeof boxVariants>["mb"]>;
	mr?: ResponsiveValue<VariantProps<typeof boxVariants>["mr"]>;
	ml?: ResponsiveValue<VariantProps<typeof boxVariants>["ml"]>;

	// Width and Height
	width?: ResponsiveValue<VariantProps<typeof boxVariants>["width"]>;
	height?: ResponsiveValue<VariantProps<typeof boxVariants>["height"]>;
	maxWidth?: ResponsiveValue<VariantProps<typeof boxVariants>["maxWidth"]>;
	minWidth?: ResponsiveValue<VariantProps<typeof boxVariants>["minWidth"]>;
	maxHeight?: ResponsiveValue<VariantProps<typeof boxVariants>["maxHeight"]>;
	minHeight?: ResponsiveValue<VariantProps<typeof boxVariants>["minHeight"]>;

	// Visual styling
	bg?: ResponsiveValue<VariantProps<typeof boxVariants>["bg"]>;
	border?: ResponsiveValue<VariantProps<typeof boxVariants>["border"]>;
	borderColor?: ResponsiveValue<
		VariantProps<typeof boxVariants>["borderColor"]
	>;
	rounded?: ResponsiveValue<VariantProps<typeof boxVariants>["rounded"]>;
	shadow?: ResponsiveValue<VariantProps<typeof boxVariants>["shadow"]>;

	// Other utilities
	overflow?: ResponsiveValue<VariantProps<typeof boxVariants>["overflow"]>;
	zIndex?: ResponsiveValue<VariantProps<typeof boxVariants>["zIndex"]>;
	opacity?: ResponsiveValue<VariantProps<typeof boxVariants>["opacity"]>;

	// Grid specific properties
	gridTemplateColumns?: string;
	gridTemplateRows?: string;
	gridColumn?: string;
	gridRow?: string;
	gridAutoFlow?: string;
	gridAutoColumns?: string;
	gridAutoRows?: string;

	// Legacy support for responsive object
	responsive?: {
		base?: Partial<Omit<BoxProps, "responsive" | "as">>;
		sm?: Partial<Omit<BoxProps, "responsive" | "as">>;
		md?: Partial<Omit<BoxProps, "responsive" | "as">>;
		lg?: Partial<Omit<BoxProps, "responsive" | "as">>;
		xl?: Partial<Omit<BoxProps, "responsive" | "as">>;
		"2xl"?: Partial<Omit<BoxProps, "responsive" | "as">>;
	};
}

/**
 * Box component - A versatile layout primitive for consistent UI construction
 *
 * @example
 * // Basic usage
 * <Box p={4} rounded="lg" shadow="md" bg="background">Content</Box>
 *
 * @example
 * // Responsive props
 * <Box p={{ base: 4, md: 6, lg: 8 }} bg={{ base: "muted", lg: "accent" }}>
 *   Responsive Box
 * </Box>
 */
export const Box = memo(
	forwardRef<HTMLDivElement, BoxProps>(
		(
			{
				as,
				className,
				children,
				display,
				position,
				direction,
				align,
				justify,
				wrap,
				gap,
				p,
				px,
				py,
				m,
				mx,
				my,
				width,
				height,
				maxWidth,
				minWidth,
				maxHeight,
				minHeight,
				bg,
				border,
				borderColor,
				rounded,
				shadow,
				overflow,
				zIndex,
				opacity,
				hoverStyles,
				focusStyles,
				activeStyles,
				animate,
				responsive,
				gridTemplateColumns,
				gridTemplateRows,
				gridColumn,
				gridRow,
				gridAutoFlow,
				gridAutoColumns,
				gridAutoRows,
				...props
			},
			ref,
		) => {
			const Component = as || "div";

			// Extract non-responsive variant props
			const standardProps: Record<string, any> = {};
			const responsiveProps: Record<string, Record<string, any>> = {};

			// Sort props into standard vs responsive
			Object.entries({
				display,
				position,
				direction,
				align,
				justify,
				wrap,
				gap,
				p,
				px,
				py,
				m,
				mx,
				my,
				width,
				height,
				maxWidth,
				minWidth,
				maxHeight,
				minHeight,
				bg,
				border,
				borderColor,
				rounded,
				shadow,
				overflow,
				zIndex,
				opacity,
			}).forEach(([key, value]) => {
				if (value !== undefined) {
					if (
						typeof value === "object" &&
						value !== null &&
						!Array.isArray(value)
					) {
						// This is a responsive value
						Object.entries(value).forEach(([breakpoint, breakpointValue]) => {
							if (!responsiveProps[breakpoint]) {
								responsiveProps[breakpoint] = {};
							}
							responsiveProps[breakpoint][key] = breakpointValue;
						});
					} else {
						// This is a standard value
						standardProps[key] = value;
					}
				}
			});

			// Handle direct grid props outside of variants
			const gridProps: Record<string, string> = {};
			if (gridTemplateColumns)
				gridProps.gridTemplateColumns = gridTemplateColumns;
			if (gridTemplateRows) gridProps.gridTemplateRows = gridTemplateRows;
			if (gridColumn) gridProps.gridColumn = gridColumn;
			if (gridRow) gridProps.gridRow = gridRow;
			if (gridAutoFlow) gridProps.gridAutoFlow = gridAutoFlow;
			if (gridAutoColumns) gridProps.gridAutoColumns = gridAutoColumns;
			if (gridAutoRows) gridProps.gridAutoRows = gridAutoRows;

			// Handle animation
			const animationClass = animate
				? "transition-all duration-300 ease-in-out"
				: "";

			// Handle interaction styles
			const interactionClasses = [
				hoverStyles ? `hover:${hoverStyles}` : "",
				focusStyles ? `focus:${focusStyles}` : "",
				activeStyles ? `active:${activeStyles}` : "",
			]
				.filter(Boolean)
				.join(" ");

			// Process standard variants
			const variantClasses = boxVariants(standardProps as any);

			// Build responsive classes
			const responsiveClasses: string[] = [];

			// Process the sorted responsive props
			Object.entries(responsiveProps).forEach(
				([breakpoint, breakpointProps]) => {
					// For base breakpoint, don't add a prefix
					const prefix = breakpoint === "base" ? "" : `${breakpoint}:`;

					// Get variant classes for this breakpoint's props
					try {
						const breakpointClasses = boxVariants(breakpointProps as any);
						if (breakpointClasses) {
							(Array.isArray(breakpointClasses)
								? breakpointClasses
								: [breakpointClasses]
							)
								.filter(Boolean)
								.forEach((cls) => {
									if (typeof cls === "string") {
										responsiveClasses.push(`${prefix}${cls}`);
									}
								});
						}
					} catch (err) {
						if (process.env.NODE_ENV === "development") {
							console.warn(
								`Error processing responsive props for breakpoint ${breakpoint}:`,
								err,
							);
						}
					}
				},
			);

			// Process the responsive object if provided
			if (responsive) {
				Object.entries(responsive).forEach(([breakpoint, breakpointProps]) => {
					// For base breakpoint, don't add a prefix
					const prefix = breakpoint === "base" ? "" : `${breakpoint}:`;

					// Get variant classes for this breakpoint's props
					try {
						const breakpointClasses = boxVariants(breakpointProps as any);
						if (breakpointClasses) {
							(Array.isArray(breakpointClasses)
								? breakpointClasses
								: [breakpointClasses]
							)
								.filter(Boolean)
								.forEach((cls) => {
									if (typeof cls === "string") {
										responsiveClasses.push(`${prefix}${cls}`);
									}
								});
						}
					} catch (err) {
						if (process.env.NODE_ENV === "development") {
							console.warn(
								`Error processing responsive props for breakpoint ${breakpoint}:`,
								err,
							);
						}
					}
				});
			}

			return (
				<Component
					ref={ref}
					className={cn(
						variantClasses,
						animationClass,
						interactionClasses,
						responsiveClasses.join(" "),
						className,
					)}
					style={Object.keys(gridProps).length > 0 ? gridProps : undefined}
					{...props}
				>
					{children}
				</Component>
			);
		},
	),
);

Box.displayName = "Box";

/**
 * Container - A centered, width-constrained Box with responsive padding
 */
export const Container = memo(
	forwardRef<HTMLDivElement, Omit<BoxProps, "mx" | "maxWidth">>(
		(props, ref) => (
			<Box
				ref={ref}
				mx="auto"
				px={4}
				width="full"
				maxWidth="7xl"
				responsive={{
					lg: { px: 6 },
				}}
				{...props}
			/>
		),
	),
);
Container.displayName = "Container";

/**
 * Flex - A convenience component for flex layouts
 */
export const Flex = memo(
	forwardRef<HTMLDivElement, Omit<BoxProps, "display">>((props, ref) => (
		<Box ref={ref} display="flex" {...props} />
	)),
);
Flex.displayName = "Flex";

/**
 * Grid - A convenience component for grid layouts
 */
export const Grid = memo(
	forwardRef<HTMLDivElement, Omit<BoxProps, "display">>((props, ref) => (
		<Box ref={ref} display="grid" {...props} />
	)),
);
Grid.displayName = "Grid";

/**
 * Card - A pre-styled Box for card layouts
 */
export const Card = memo(
	forwardRef<HTMLDivElement, BoxProps>((props, ref) => (
		<Box
			ref={ref}
			p={5}
			bg="background"
			border="default"
			borderColor="border"
			rounded="lg"
			shadow="md"
			overflow="hidden"
			{...props}
		/>
	)),
);
Card.displayName = "Card";

/**
 * Divider - A horizontal or vertical separator line
 */
export const Divider = memo(
	forwardRef<
		HTMLDivElement,
		BoxProps & { orientation?: "horizontal" | "vertical" }
	>(({ orientation = "horizontal", className, ...props }, ref) => (
		<Box
			ref={ref}
			className={cn(
				orientation === "horizontal" ? "w-full h-px" : "h-full w-px",
				className,
			)}
			bg="muted"
			my={orientation === "horizontal" ? 4 : 0}
			mx={orientation === "vertical" ? 4 : 0}
			{...props}
		/>
	)),
);
Divider.displayName = "Divider";
