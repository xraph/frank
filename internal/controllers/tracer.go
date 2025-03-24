package controllers

// import (
// 	"context"
//
// 	"go.opentelemetry.io/otel"
// 	"go.opentelemetry.io/otel/sdk/trace"
// )
//
// func initTracer() (func(), error) {
// 	// Create an exporter (e.g., Jaeger, Zipkin, OTLP)
// 	exporter, err := otlptracegrpc.New(context.Background())
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	// Create a trace provider with the exporter
// 	tp := trace.NewTracerProvider(
// 		trace.WithBatcher(exporter),
// 		trace.WithSampler(trace.AlwaysSample()),
// 	)
//
// 	// Set the global trace provider
// 	otel.SetTracerProvider(tp)
//
// 	// Return a cleanup function
// 	return func() {
// 		_ = tp.Shutdown(context.Background())
// 	}, nil
// }
