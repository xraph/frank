package server

import (
	"fmt"
	"strings"
)

// BannerConfig holds configuration for the startup banner
type BannerConfig struct {
	Enabled     bool
	Title       string
	Version     string
	Environment string
	Icon        string
	Width       int
	BorderChar  string
	FillChar    string
}

// DefaultBanner returns default banner configuration
func DefaultBanner() BannerConfig {
	return BannerConfig{
		Enabled:     true,
		Title:       "Frank Auth Server is starting",
		Version:     "1.0.0",
		Environment: "development",
		Icon:        "🚀",
		Width:       55,
		BorderChar:  "═",
		FillChar:    " ",
	}
}

// PrintBanner prints a formatted banner with the given configuration
func PrintBanner(config BannerConfig) {
	if !config.Enabled {
		return
	}

	width := config.Width
	borderChar := config.BorderChar
	fillChar := config.FillChar

	// Top border
	fmt.Printf("╭%s╮\n", strings.Repeat(borderChar, width))

	// Empty line
	fmt.Printf("│%s│\n", strings.Repeat(fillChar, width))

	// Title line
	titleLine := fmt.Sprintf("%s %s", config.Icon, config.Title)
	padding := width - len(titleLine)
	fmt.Printf("│%s%s%s│\n", titleLine, strings.Repeat(fillChar, padding), fillChar)

	// Version line
	versionLine := fmt.Sprintf("   Version: %s", config.Version)
	padding = width - len(versionLine)
	fmt.Printf("│%s%s│\n", versionLine, strings.Repeat(fillChar, padding))

	// Environment line
	envLine := fmt.Sprintf("   Environment: %s", config.Environment)
	padding = width - len(envLine)
	fmt.Printf("│%s%s│\n", envLine, strings.Repeat(fillChar, padding))

	// Empty line
	fmt.Printf("│%s│\n", strings.Repeat(fillChar, width))

	// Bottom border
	fmt.Printf("╰%s╯\n", strings.Repeat(borderChar, width))
}
