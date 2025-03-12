package swaggergen

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/go-chi/chi/v5"
	"gopkg.in/yaml.v3"
)

// OpenAPIGenerator holds the Chi router and the OpenAPI specification.
type OpenAPIGenerator struct {
	Router chi.Router
	Spec   *openapi3.T
}

// NewOpenAPIGenerator creates a new generator with basic OpenAPI fields.
func NewOpenAPIGenerator(router chi.Router, info *openapi3.Info) *OpenAPIGenerator {
	spec := &openapi3.T{
		OpenAPI: "3.0.0",
		Info:    info,
		Paths:   &openapi3.Paths{},
	}

	return &OpenAPIGenerator{
		Router: router,
		Spec:   spec,
	}
}

// ParseRoutes walks the Chi router, populating .Spec with Paths and Operations.
func (g *OpenAPIGenerator) ParseRoutes() error {
	if g.Router == nil {
		return errors.New("chi router is nil")
	}

	// Walk function is called for every route in the router.
	walkFn := func(method string, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		// Skip the default "/*" route
		if route == "/*" {
			return nil
		}

		// Convert Chi route to an OpenAPI path (e.g. "/users/{userID}")
		openAPIPath := chiPathToOpenAPIPath(route)

		// Make sure the path exists in the OpenAPI spec
		if found := g.Spec.Paths.Value(openAPIPath); found != nil {
			g.Spec.Paths.Set(openAPIPath, &openapi3.PathItem{})
		}
		pathItem := g.Spec.Paths.Value(openAPIPath)

		// Build the operation
		operation := &openapi3.Operation{
			Responses: openapi3.NewResponses(),
			// You can set other fields here (e.g. Summary, Description, etc.)
			Parameters: extractPathParameters(route),
		}

		// Attach the operation to the pathItem based on method
		switch strings.ToUpper(method) {
		case http.MethodGet:
			pathItem.Get = operation
		case http.MethodPost:
			pathItem.Post = operation
		case http.MethodPut:
			pathItem.Put = operation
		case http.MethodDelete:
			pathItem.Delete = operation
		case http.MethodPatch:
			pathItem.Patch = operation
		case http.MethodOptions:
			pathItem.Options = operation
		case http.MethodHead:
			pathItem.Head = operation
		}

		return nil
	}

	if err := chi.Walk(g.Router, walkFn); err != nil {
		return fmt.Errorf("error walking chi routes: %w", err)
	}
	return nil
}

// extractPathParameters finds occurrences of Chi-style path params {param} and
// creates an OpenAPI parameter definition for each.
func extractPathParameters(route string) openapi3.Parameters {
	re := regexp.MustCompile(`\{([^{}]+)\}`)
	matches := re.FindAllStringSubmatch(route, -1)
	if len(matches) == 0 {
		return nil
	}

	params := make(openapi3.Parameters, 0)
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		name := m[1]
		params = append(params, &openapi3.ParameterRef{
			Value: &openapi3.Parameter{
				Name:     name,
				In:       openapi3.ParameterInPath,
				Required: true,
				Schema: &openapi3.SchemaRef{
					Value: &openapi3.Schema{
						Type: &openapi3.Types{openapi3.TypeString},
					},
				},
			},
		})
	}
	return params
}

// chiPathToOpenAPIPath simply returns the same route pattern with * removed.
func chiPathToOpenAPIPath(route string) string {
	// Chi wildcard is "*", remove it to match OpenAPI patterns
	return strings.ReplaceAll(route, "*", "")
}

// SaveJSON writes the OpenAPI specification to a JSON file.
func (g *OpenAPIGenerator) SaveJSON(filename string) error {
	data, err := json.MarshalIndent(g.Spec, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal to JSON: %w", err)
	}
	return os.WriteFile(filename, data, 0o644)
}

// SaveYAML writes the OpenAPI specification to a YAML file.
func (g *OpenAPIGenerator) SaveYAML(filename string) error {
	data, err := yaml.Marshal(g.Spec)
	if err != nil {
		return fmt.Errorf("failed to marshal to YAML: %w", err)
	}
	return os.WriteFile(filename, data, 0o644)
}
