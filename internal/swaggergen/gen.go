package swaggergen

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/go-chi/chi/v5"
	"github.com/oasdiff/yaml"
)

// SwaggerGen generates OpenAPI 3.0 documentation from Chi router
type SwaggerGen struct {
	Router      chi.Router
	API         *openapi3.T
	RouteParams map[string][]string // Maps route patterns to param names
}

// NewSwaggerGen creates a new Swagger generator for a Chi router
func NewSwaggerGen(r chi.Router, info *openapi3.Info) *SwaggerGen {
	description := "Default response"
	api := &openapi3.T{
		OpenAPI: "3.0.0",
		Info:    info,
		Paths:   &openapi3.Paths{},
		Components: &openapi3.Components{
			Schemas:    make(openapi3.Schemas),
			Parameters: make(openapi3.ParametersMap),
			RequestBodies: openapi3.RequestBodies{
				"JsonBody": &openapi3.RequestBodyRef{
					Value: &openapi3.RequestBody{
						Description: "JSON request body",
						Content: openapi3.Content{
							"application/json": &openapi3.MediaType{
								Schema: &openapi3.SchemaRef{
									Value: &openapi3.Schema{
										Type:                 &openapi3.Types{openapi3.TypeObject},
										AdditionalProperties: openapi3.AdditionalProperties{},
									},
								},
							},
						},
					},
				},
			},
			Responses: openapi3.ResponseBodies{
				"DefaultResponse": &openapi3.ResponseRef{
					Value: &openapi3.Response{
						Description: &description,
						Content: openapi3.Content{
							"application/json": &openapi3.MediaType{
								Schema: &openapi3.SchemaRef{
									Value: &openapi3.Schema{
										Type: &openapi3.Types{openapi3.TypeObject},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	return &SwaggerGen{
		Router:      r,
		API:         api,
		RouteParams: make(map[string][]string),
	}
}

// ExtractRoutes walks the Chi router tree and extracts routes
func (sg *SwaggerGen) ExtractRoutes() error {
	// Create a walkFn to process each route
	walkFn := func(method, route string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		// Skip the "/*" catch-all route that Chi adds by default
		if route == "/*" {
			return nil
		}

		// Extract path parameters
		params := sg.extractPathParams(route)
		sg.RouteParams[route] = params

		// Create path item if it doesn't exist
		pathPattern := sg.convertChiRouteToOpenAPI(route)
		if sg.API.Paths.Value(pathPattern) == nil {
			sg.API.Paths.Set(pathPattern, &openapi3.PathItem{})
		}

		// Create operation
		operation := &openapi3.Operation{
			Responses: &openapi3.Responses{
				// "200": &openapi3.ResponseRef{
				// 	Ref: "#/components/responses/DefaultResponse",
				// },
			},
			Parameters: sg.createPathParameters(params),
		}

		// Add operation to the path based on HTTP method
		switch method {
		case http.MethodGet:
			sg.API.Paths.Value(pathPattern).Get = operation
		case http.MethodPost:
			sg.API.Paths.Value(pathPattern).Post = operation
			// Add request body for POST
			operation.RequestBody = &openapi3.RequestBodyRef{
				Ref: "#/components/requestBodies/JsonBody",
			}
		case http.MethodPut:
			sg.API.Paths.Value(pathPattern).Put = operation
			// Add request body for PUT
			operation.RequestBody = &openapi3.RequestBodyRef{
				Ref: "#/components/requestBodies/JsonBody",
			}
		case http.MethodDelete:
			sg.API.Paths.Value(pathPattern).Delete = operation
		case http.MethodPatch:
			sg.API.Paths.Value(pathPattern).Patch = operation
			// Add request body for PATCH
			operation.RequestBody = &openapi3.RequestBodyRef{
				Ref: "#/components/requestBodies/JsonBody",
			}
		case http.MethodOptions:
			sg.API.Paths.Value(pathPattern).Options = operation
		case http.MethodHead:
			sg.API.Paths.Value(pathPattern).Head = operation
		}

		return nil
	}

	// Walk the router
	if err := chi.Walk(sg.Router, walkFn); err != nil {
		return fmt.Errorf("error walking routes: %w", err)
	}

	return nil
}

// extractPathParams extracts parameter names from a Chi route pattern
func (sg *SwaggerGen) extractPathParams(route string) []string {
	// Chi uses {paramName} for path parameters
	re := regexp.MustCompile(`\{([^{}]+)\}`)
	matches := re.FindAllStringSubmatch(route, -1)

	params := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) > 1 {
			params = append(params, match[1])
		}
	}

	return params
}

// convertChiRouteToOpenAPI converts Chi route pattern to OpenAPI path pattern
func (sg *SwaggerGen) convertChiRouteToOpenAPI(route string) string {
	// Replace {paramName} with {paramName}
	// Chi and OpenAPI use the same format, but we need to handle wildcards
	route = strings.ReplaceAll(route, "*", "") // Remove wildcards

	return route
}

// createPathParameters creates OpenAPI parameters for path parameters
func (sg *SwaggerGen) createPathParameters(params []string) openapi3.Parameters {
	result := make(openapi3.Parameters, 0, len(params))

	for _, param := range params {
		result = append(result, &openapi3.ParameterRef{
			Value: &openapi3.Parameter{
				Name:     param,
				In:       "path",
				Required: true,
				Schema: &openapi3.SchemaRef{
					Value: &openapi3.Schema{
						Type: &openapi3.Types{openapi3.TypeString},
					},
				},
			},
		})
	}

	return result
}

// AddSchema adds a model schema to the components section
func (sg *SwaggerGen) AddSchema(name string, model interface{}) {
	schema := sg.modelToSchema(reflect.TypeOf(model))
	sg.API.Components.Schemas[name] = &openapi3.SchemaRef{Value: schema}
}

// modelToSchema converts a Go struct to an OpenAPI schema
func (sg *SwaggerGen) modelToSchema(t reflect.Type) *openapi3.Schema {
	// Handle pointer types
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}

	// Handle non-struct types directly
	if t.Kind() != reflect.Struct {
		return sg.typeToSchema(t)
	}

	schema := &openapi3.Schema{
		Type:       &openapi3.Types{openapi3.TypeObject},
		Properties: make(openapi3.Schemas),
	}

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)

		// Skip unexported fields
		if field.PkgPath != "" {
			continue
		}

		// Get JSON field name from tag or use struct field name
		jsonTag := field.Tag.Get("json")
		jsonName := field.Name
		if jsonTag != "" {
			parts := strings.Split(jsonTag, ",")
			if parts[0] != "" && parts[0] != "-" {
				jsonName = parts[0]
			}
		}

		// Add property to schema
		propSchema := sg.typeToSchema(field.Type)

		// Check for required from json tag
		if !strings.Contains(jsonTag, "omitempty") {
			schema.Required = append(schema.Required, jsonName)
		}

		// Add description from struct tag if available
		if desc := field.Tag.Get("description"); desc != "" {
			propSchema.Description = desc
		}

		schema.Properties[jsonName] = &openapi3.SchemaRef{Value: propSchema}
	}

	return schema
}

// typeToSchema converts a Go type to an OpenAPI schema
func (sg *SwaggerGen) typeToSchema(t reflect.Type) *openapi3.Schema {
	// Handle pointer types
	if t.Kind() == reflect.Ptr {
		return sg.typeToSchema(t.Elem())
	}

	switch t.Kind() {
	case reflect.Bool:
		return &openapi3.Schema{Type: &openapi3.Types{openapi3.TypeBoolean}}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return &openapi3.Schema{Type: &openapi3.Types{openapi3.TypeInteger}}
	case reflect.Float32, reflect.Float64:
		return &openapi3.Schema{Type: &openapi3.Types{openapi3.TypeNumber}}
	case reflect.String:
		return &openapi3.Schema{Type: &openapi3.Types{openapi3.TypeString}}
	case reflect.Struct:
		if t.String() == "time.Time" {
			return &openapi3.Schema{
				Type:   &openapi3.Types{openapi3.TypeString},
				Format: "date-time",
			}
		}
		return sg.modelToSchema(t)
	case reflect.Slice, reflect.Array:
		return &openapi3.Schema{
			Type:  &openapi3.Types{openapi3.TypeArray},
			Items: &openapi3.SchemaRef{Value: sg.typeToSchema(t.Elem())},
		}
	case reflect.Map:
		return &openapi3.Schema{
			Type: &openapi3.Types{openapi3.TypeObject},
			AdditionalProperties: openapi3.AdditionalProperties{
				Schema: &openapi3.SchemaRef{Value: sg.typeToSchema(t.Elem())},
			},
		}
	default:
		return &openapi3.Schema{Type: &openapi3.Types{openapi3.TypeObject}}
	}
}

// AddPathDescription adds a description to a path operation
func (sg *SwaggerGen) AddPathDescription(method, path, description string) error {
	// Convert Chi path to OpenAPI path
	openapiPath := sg.convertChiRouteToOpenAPI(path)

	// Get the path item
	pathItem := sg.API.Paths.Value(openapiPath)
	if pathItem == nil {
		return fmt.Errorf("path %s not found", path)
	}

	// Update the operation description
	var operation *openapi3.Operation
	switch strings.ToUpper(method) {
	case "GET":
		operation = pathItem.Get
	case "POST":
		operation = pathItem.Post
	case "PUT":
		operation = pathItem.Put
	case "DELETE":
		operation = pathItem.Delete
	case "PATCH":
		operation = pathItem.Patch
	case "OPTIONS":
		operation = pathItem.Options
	case "HEAD":
		operation = pathItem.Head
	default:
		return fmt.Errorf("invalid HTTP method: %s", method)
	}

	if operation == nil {
		return fmt.Errorf("operation %s %s not found", method, path)
	}

	operation.Description = description
	return nil
}

// AddTag adds a tag to the OpenAPI document
func (sg *SwaggerGen) AddTag(name, description string) {
	tag := &openapi3.Tag{
		Name:        name,
		Description: description,
	}
	sg.API.Tags = append(sg.API.Tags, tag)
}

// AddPathTag adds a tag to a specific path operation
func (sg *SwaggerGen) AddPathTag(method, path, tag string) error {
	// Convert Chi path to OpenAPI path
	openapiPath := sg.convertChiRouteToOpenAPI(path)

	// Get the path item
	pathItem := sg.API.Paths.Value(openapiPath)
	if pathItem == nil {
		return fmt.Errorf("path %s not found", path)
	}

	// Update the operation tags
	var operation *openapi3.Operation
	switch strings.ToUpper(method) {
	case "GET":
		operation = pathItem.Get
	case "POST":
		operation = pathItem.Post
	case "PUT":
		operation = pathItem.Put
	case "DELETE":
		operation = pathItem.Delete
	case "PATCH":
		operation = pathItem.Patch
	case "OPTIONS":
		operation = pathItem.Options
	case "HEAD":
		operation = pathItem.Head
	default:
		return fmt.Errorf("invalid HTTP method: %s", method)
	}

	if operation == nil {
		return fmt.Errorf("operation %s %s not found", method, path)
	}

	operation.Tags = append(operation.Tags, tag)
	return nil
}

// SaveJSON saves the OpenAPI specification to a JSON file
func (sg *SwaggerGen) SaveJSON(filename string) error {
	data, err := json.MarshalIndent(sg.API, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling to JSON: %w", err)
	}

	err = os.WriteFile(filename, data, 0644)
	if err != nil {
		return fmt.Errorf("error writing to file: %w", err)
	}

	return nil
}

// SaveYAML saves the OpenAPI specification to a YAML file
func (sg *SwaggerGen) SaveYAML(filename string) error {
	data, err := yaml.Marshal(sg.API)
	if err != nil {
		return fmt.Errorf("error marshaling to YAML: %w", err)
	}

	err = os.WriteFile(filename, data, 0644)
	if err != nil {
		return fmt.Errorf("error writing to file: %w", err)
	}

	return nil
}
