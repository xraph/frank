package server

import (
	"github.com/spf13/cobra"
)

func StartCMD(server *Server) func(cmd *cobra.Command, args []string) {
	return func(cmd *cobra.Command, args []string) {
		server.Start()
	}
}

func NewStartCMD(server *Server, banner *BannerConfig) *cobra.Command {
	var cmd = &cobra.Command{
		Use:   "start",
		Short: "OnStart the server",
		Run:   StartCMD(server),
	}

	cmd.Flags().BoolVar(&banner.Enabled, "banner", true, "Enable or disable startup banner")
	cmd.Flags().StringVar(&banner.Title, "banner-title", banner.Title, "Set the banner title")
	cmd.Flags().StringVar(&banner.Icon, "banner-icon", banner.Icon, "Set the banner icon")
	cmd.Flags().IntVar(&banner.Width, "banner-width", banner.Width, "Set the banner width")
	cmd.Flags().StringVar(&banner.BorderChar, "banner-border", banner.BorderChar, "Set the banner border character")

	return cmd
}

func StopCMD(server *Server) func(cmd *cobra.Command, args []string) {
	return func(cmd *cobra.Command, args []string) {
		server.Stop()
	}
}
