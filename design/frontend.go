package design

import (
	. "goa.design/goa/v3/dsl"
)

var _ = Service("admin", func() {
	// Serve the React app
	Files("/admin/{*filepath}", "ui/build")

	// Serve static assets directly
	Files("/robots.txt", "admin/public/robots.txt")
	Files("/favicon.ico", "admin/public/favicon.ico")

	Method("home", func() {
		Description("Render the home page")
		NoSecurity()

		HTTP(func() {
			GET("/")
			GET("/admin")
			Redirect("/admin/", StatusMovedPermanently) // Redirect root to /ui/
		})
	})
})

var _ = Service("web", func() {
	Description("Front-end web service with template rendering")

	// Serve the React app
	Files("/ui/{*filepath}", "./web/apps/client/dist")

	// Serve static assets directly
	// Files("/robots.txt", "ui/public/robots.txt")
	// Files("/favicon.ico", "ui/public/favicon.ico")

	Method("home", func() {
		Description("Render the home page")
		NoSecurity()

		HTTP(func() {
			GET("/")
			GET("/ui")
			Redirect("/ui/", StatusMovedPermanently) // Redirect root to /ui/
		})
	})
})
