package main

import (
	"net/http"
	"time"

	cli "github.com/juicycleff/frank/gen/http/cli/frank"
	goahttp "goa.design/goa/v3/http"
	goa "goa.design/goa/v3/pkg"
)

func doHTTP(scheme, host string, timeout int, debug bool) (goa.Endpoint, any, error) {
	var (
		doer goahttp.Doer
		// interceptorsInterceptors interceptors.ClientInterceptors
	)
	{
		doer = &http.Client{Timeout: time.Duration(timeout) * time.Second}
		if debug {
			doer = goahttp.NewDebugDoer(doer)
		}
		// interceptorsInterceptors = interceptorsex.NewInterceptorsClientInterceptors()
	}

	// var (
	// 	dialer *websocket.Dialer
	// )
	// {
	// 	dialer = websocket.DefaultDialer
	// }

	return cli.ParseEndpoint(
		scheme,
		host,
		doer,
		goahttp.RequestEncoder,
		goahttp.ResponseDecoder,
		// debug,
		// dialer,
		true,
		// nil,
		// interceptorsInterceptors,
	)
}

func httpUsageCommands() string {
	return cli.UsageCommands()
}

func httpUsageExamples() string {
	return cli.UsageExamples()
}
