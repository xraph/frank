package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

func main() {
	// Define command-line flags
	var (
		routerPkg    string
		routerFunc   string
		outputFile   string
		title        string
		description  string
		version      string
		contactName  string
		contactEmail string
		contactURL   string
		license      string
		licenseURL   string
		jsonFormat   bool
		yamlFormat   bool
		swaggerUIDir string
		serverURLs   string
	)

	flag.StringVar(&routerPkg, "pkg", "main", "Package containing the router initialization")
	flag.StringVar(&routerFunc, "func", "NewRouter", "Function that returns the chi.Router")
	flag.StringVar(&outputFile, "output", "openapi.json", "Output file path")
	flag.StringVar(&title, "title", "API Documentation", "API title")
	flag.StringVar(&description, "desc", "API Documentation", "API description")
	flag.StringVar(&version, "version", "1.0.0", "API version")
	flag.StringVar(&contactName, "contact-name", "", "Contact name")
	flag.StringVar(&contactEmail, "contact-email", "", "Contact email")
	flag.StringVar(&contactURL, "contact-url", "", "Contact URL")
	flag.StringVar(&license, "license", "", "License name")
	flag.StringVar(&licenseURL, "license-url", "", "License URL")
	flag.BoolVar(&jsonFormat, "json", true, "Output in JSON format")
	flag.BoolVar(&yamlFormat, "yaml", false, "Output in YAML format")
	flag.StringVar(&swaggerUIDir, "swagger-ui", "", "Directory to generate Swagger UI files")
	flag.StringVar(&serverURLs, "servers", "", "Comma-separated list of server URLs")

	flag.Parse()

	// Validate output format
	if !jsonFormat && !yamlFormat {
		fmt.Println("Error: At least one of -json or -yaml must be enabled")
		os.Exit(1)
	}

	// Create OpenAPI info
	info := &openapi3.Info{
		Title:       title,
		Description: description,
		Version:     version,
	}

	// Add contact info if provided
	if contactName != "" || contactEmail != "" || contactURL != "" {
		info.Contact = &openapi3.Contact{
			Name:  contactName,
			Email: contactEmail,
			URL:   contactURL,
		}
	}

	// Add license info if provided
	if license != "" {
		info.License = &openapi3.License{
			Name: license,
			URL:  licenseURL,
		}
	}

	// Parse server URLs if provided
	var servers []*openapi3.Server
	if serverURLs != "" {
		urlList := strings.Split(serverURLs, ",")
		for _, url := range urlList {
			servers = append(servers, &openapi3.Server{
				URL:         strings.TrimSpace(url),
				Description: fmt.Sprintf("Server %d", len(servers)+1),
			})
		}
	}

	// Create temporary file to inject router initialization
	tmpFile := filepath.Join(os.TempDir(), "chi_openapi_gen.go")
	if err := generateRouterInit(tmpFile, routerPkg, routerFunc, info, servers); err != nil {
		fmt.Printf("Error generating router initialization: %v\n", err)
		os.Exit(1)
	}
	defer os.Remove(tmpFile)

	// Build and run the generator
	if err := buildAndRunGenerator(tmpFile, outputFile, jsonFormat, yamlFormat); err != nil {
		fmt.Printf("Error building or running generator: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("OpenAPI documentation generated: %s\n", outputFile)

	// Generate Swagger UI if requested
	if swaggerUIDir != "" {
		if err := generateSwaggerUI(swaggerUIDir, outputFile); err != nil {
			fmt.Printf("Error generating Swagger UI: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Swagger UI generated in: %s\n", swaggerUIDir)
	}
}

// generateRouterInit creates a temporary Go file that initializes the router
// and generates OpenAPI documentation
func generateRouterInit(outFile, routerPkg, routerFunc string, info *openapi3.Info, servers []*openapi3.Server) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(outFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Create the file
	f, err := os.Create(outFile)
	if err != nil {
		return err
	}
	defer f.Close()

	// Write the code
	code := `package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/go-chi/chi/v5"
	"gopkg.in/yaml.v3"
	"%s"
)

// SwaggerGen generates OpenAPI documentation from Chi router
type SwaggerGen struct {
	router      chi.Router
	routeInfo   []RouteInfo
	OpenAPI     *openapi3.T
	components  map[string]*openapi3.SchemaRef
	paths       map[string]*openapi3.PathItem
	handlerDesc map[string]HandlerDescription
}

// RouteInfo stores information about a route
type RouteInfo struct {
	Method      string
	Pattern     string
	HandlerName string
}

// HandlerDescription stores documentation for a handler
type HandlerDescription struct {
	Summary     string
	Description string
	Tags        []string
}

// NewSwaggerGen creates a new swagger generator
func NewSwaggerGen(router chi.Router, info *openapi3.Info, servers []*openapi3.Server) *SwaggerGen {
	openAPI := &openapi3.T{
		OpenAPI: "3.0.3",
		Info:    info,
		Paths:   openapi3.Paths{},
		Components: &openapi3.Components{
			Schemas:    make(openapi3.Schemas),
			Responses:  make(openapi3.Responses),
			Parameters: make(openapi3.ParametersMap),
			RequestBodies: make(openapi3.RequestBodies),
			SecuritySchemes: openapi3.SecuritySchemes{
				"BearerAuth": &openapi3.SecuritySchemeRef{
					Value: &openapi3.SecurityScheme{
						Type:         "http",
						Scheme:       "bearer",
						BearerFormat: "JWT",
					},
				},
				"ApiKeyAuth": &openapi3.SecuritySchemeRef{
					Value: &openapi3.SecurityScheme{
						Type: "apiKey",
						In:   "header",
						Name: "X-API-Key",
					},
				},
			},
		},
		Security: openapi3.SecurityRequirements{
			{
				"BearerAuth": []string{},
			},
			{
				"ApiKeyAuth": []string{},
			},
		},
		Servers: servers,
	}

	return &SwaggerGen{
		router:      router,
		OpenAPI:     openAPI,
		components:  make(map[string]*openapi3.SchemaRef),
		paths:       make(map[string]*openapi3.PathItem),
		handlerDesc: make(map[string]HandlerDescription),
	}
}

// ExtractRoutes extracts all routes from the Chi router
func (sg *SwaggerGen) ExtractRoutes() error {
	walkFunc := func(method string, route string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		handlerName := getHandlerName(handler)
		
		// Skip middleware handlers and special paths
		if strings.Contains(handlerName, "middleware") || 
		   strings.Contains(route, "/docs") || 
		   strings.Contains(route, "/static") {
			return nil
		}

		// Clean up route pattern
		pattern := route
		pattern = strings.ReplaceAll(pattern, "/*/", "/")
		pattern = strings.ReplaceAll(pattern, "/*", "")
		
		// Store route info
		sg.routeInfo = append(sg.routeInfo, RouteInfo{
			Method:      method,
			Pattern:     pattern,
			HandlerName: handlerName,
		})
		
		// Add path to OpenAPI spec
		sg.addPath(method, pattern, handlerName)
		
		return nil
	}

	// Use the Chi walker to extract all routes
	return chi.Walk(sg.router, walkFunc)
}

// addPath adds a path to the OpenAPI spec
func (sg *SwaggerGen) addPath(method string, pattern string, handlerName string) {
	// Convert pattern format from Chi to OpenAPI
	openAPIPath := convertChiPathToOpenAPI(pattern)
	
	// Get or create path item
	pathItem, ok := sg.paths[openAPIPath]
	if !ok {
		pathItem = &openapi3.PathItem{}
		sg.paths[openAPIPath] = pathItem
	}
	
	// Create operation
	operation := &openapi3.Operation{
		Responses: openapi3.Responses{
			"default": &openapi3.ResponseRef{
				Value: &openapi3.Response{
					Description: openapi3.Ptr("Default response"),
				},
			},
		},
	}
	
	// Set defaults based on handler name and method
	operation.Summary = humanizeHandlerName(handlerName)
	operation.Description = fmt.Sprintf("%s endpoint", humanizeHandlerName(handlerName))
	
	// Extract tag from pattern (first segment after api/v1/)
	tag := extractTagFromPattern(pattern)
	if tag != "" {
		operation.Tags = []string{tag}
	}
	
	// Add default responses based on method
	sg.addDefaultResponses(operation, method)
	
	// Add path parameters if any
	pathParams := extractPathParams(pattern)
	for _, param := range pathParams {
		operation.Parameters = append(operation.Parameters, &openapi3.ParameterRef{
			Value: &openapi3.Parameter{
				Name:        param,
				In:          "path",
				Description: fmt.Sprintf("%s parameter", param),
				Required:    true,
				Schema: &openapi3.SchemaRef{
					Value: &openapi3.Schema{
						Type: "string",
					},
				},
			},
		})
	}
	
	// Set operation on path item based on method
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
	case http.MethodHead:
		pathItem.Head = operation
	case http.MethodOptions:
		pathItem.Options = operation
	}
	
	// Update paths in OpenAPI spec
	sg.OpenAPI.Paths[openAPIPath] = pathItem
}

// addDefaultResponses adds default responses based on method
func (sg *SwaggerGen) addDefaultResponses(operation *openapi3.Operation, method string) {
	responses := openapi3.Responses{}
	
	switch strings.ToUpper(method) {
	case http.MethodGet:
		responses["200"] = &openapi3.ResponseRef{
			Value: &openapi3.Response{
				Description: openapi3.Ptr("Successful response"),
				Content: openapi3.Content{
					"application/json": &openapi3.MediaType{
						Schema: &openapi3.SchemaRef{
							Value: &openapi3.Schema{
								Type: "object",
							},
						},
					},
				},
			},
		}
	case http.MethodPost:
		responses["201"] = &openapi3.ResponseRef{
			Value: &openapi3.Response{
				Description: openapi3.Ptr("Created successfully"),
				Content: openapi3.Content{
					"application/json": &openapi3.MediaType{
						Schema: &openapi3.SchemaRef{
							Value: &openapi3.Schema{
								Type: "object",
							},
						},
					},
				},
			},
		}
	case http.MethodPut, http.MethodPatch:
		responses["200"] = &openapi3.ResponseRef{
			Value: &openapi3.Response{
				Description: openapi3.Ptr("Updated successfully"),
				Content: openapi3.Content{
					"application/json": &openapi3.MediaType{
						Schema: &openapi3.SchemaRef{
							Value: &openapi3.Schema{
								Type: "object",
							},
						},
					},
				},
			},
		}
	case http.MethodDelete:
		responses["204"] = &openapi3.ResponseRef{
			Value: &openapi3.Response{
				Description: openapi3.Ptr("Deleted successfully"),
			},
		}
	}
	
	// Add common error responses
	responses["400"] = &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Description: openapi3.Ptr("Bad request"),
			Content: openapi3.Content{
				"application/json": &openapi3.MediaType{
					Schema: &openapi3.SchemaRef{
						Ref: "#/components/schemas/ErrorResponse",
					},
				},
			},
		},
	}
	
	responses["401"] = &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Description: openapi3.Ptr("Unauthorized"),
			Content: openapi3.Content{
				"application/json": &openapi3.MediaType{
					Schema: &openapi3.SchemaRef{
						Ref: "#/components/schemas/ErrorResponse",
					},
				},
			},
		},
	}
	
	responses["403"] = &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Description: openapi3.Ptr("Forbidden"),
			Content: openapi3.Content{
				"application/json": &openapi3.MediaType{
					Schema: &openapi3.SchemaRef{
						Ref: "#/components/schemas/ErrorResponse",
					},
				},
			},
		},
	}
	
	responses["404"] = &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Description: openapi3.Ptr("Not found"),
			Content: openapi3.Content{
				"application/json": &openapi3.MediaType{
					Schema: &openapi3.SchemaRef{
						Ref: "#/components/schemas/ErrorResponse",
					},
				},
			},
		},
	}
	
	responses["500"] = &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Description: openapi3.Ptr("Internal server error"),
			Content: openapi3.Content{
				"application/json": &openapi3.MediaType{
					Schema: &openapi3.SchemaRef{
						Ref: "#/components/schemas/ErrorResponse",
					},
				},
			},
		},
	}
	
	// Add error schema if not already defined
	if sg.OpenAPI.Components.Schemas["ErrorResponse"] == nil {
		sg.OpenAPI.Components.Schemas["ErrorResponse"] = &openapi3.SchemaRef{
			Value: &openapi3.Schema{
				Type: "object",
				Properties: openapi3.Schemas{
					"error": {
						Value: &openapi3.Schema{
							Type: "string",
						},
					},
					"message": {
						Value: &openapi3.Schema{
							Type: "string",
						},
					},
					"status": {
						Value: &openapi3.Schema{
							Type: "integer",
						},
					},
				},
				Required: []string{"error", "message", "status"},
			},
		}
	}
	
	operation.Responses = responses
}

// SaveJSON saves the OpenAPI spec as JSON
func (sg *SwaggerGen) SaveJSON(filePath string) error {
	// Ensure directory exists
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	
	// Create file
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()
	
	// Marshal to JSON
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(sg.OpenAPI)
}

// SaveYAML saves the OpenAPI spec as YAML
func (sg *SwaggerGen) SaveYAML(filePath string) error {
	// Ensure directory exists
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	
	// Create file
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()
	
	// Convert to JSON first (easier to handle)
	jsonData, err := json.Marshal(sg.OpenAPI)
	if err != nil {
		return err
	}
	
	// Convert JSON to map
	var jsonMap map[string]interface{}
	if err := json.Unmarshal(jsonData, &jsonMap); err != nil {
		return err
	}
	
	// Marshal to YAML
	encoder := yaml.NewEncoder(file)
	encoder.SetIndent(2)
	return encoder.Encode(jsonMap)
}

// Helper functions

// getHandlerName extracts the name of a handler function
func getHandlerName(handler http.Handler) string {
	// Get the function name from the pointer
	name := fmt.Sprintf("%T", handler)
	
	// For http.HandlerFunc, extract the function name
	if strings.Contains(name, "http.HandlerFunc") {
		// Use reflection to get the actual function name
		val := reflect.ValueOf(handler)
		name = runtime.FuncForPC(val.Pointer()).Name()
		
		// Extract just the function name without the package path
		parts := strings.Split(name, ".")
		return parts[len(parts)-1]
	}
	
	// For other handlers, extract the type name
	parts := strings.Split(name, ".")
	return parts[len(parts)-1]
}

// extractPathParams extracts path parameters from a Chi route pattern
func extractPathParams(pattern string) []string {
	re := regexp.MustCompile("\{([^/]+)\}")
	matches := re.FindAllStringSubmatch(pattern, -1)
	
	params := []string{}
	for _, match := range matches {
		if len(match) > 1 {
			params = append(params, match[1])
		}
	}
	
	return params
}

// convertChiPathToOpenAPI converts a Chi path format to OpenAPI path format
func convertChiPathToOpenAPI(pattern string) string {
	// Chi paths use {param} which is compatible with OpenAPI 3.0
	return pattern
}

// humanizeHandlerName converts a handler name to a human-readable description
func humanizeHandlerName(name string) string {
	// Split the name into words based on camel case
	words := splitCamelCase(name)
	
	// Convert to title case and join with spaces
	for i, word := range words {
		words[i] = strings.Title(strings.ToLower(word))
	}
	
	return strings.Join(words, " ")
}

// splitCamelCase splits a camelCase string into words
func splitCamelCase(s string) []string {
	re := regexp.MustCompile("([a-z])([A-Z])")
	s = re.ReplaceAllString(s, "$1 $2")
	return strings.Split(s, " ")
}

// extractTagFromPattern extracts a tag from a pattern
func extractTagFromPattern(pattern string) string {
	parts := strings.Split(pattern, "/")
	
	// Find the index after api/v1/
	apiVxIndex := -1
	for i, part := range parts {
		if strings.HasPrefix(part, "v") && len(part) > 1 {
			apiVxIndex = i
			break
		}
	}
	
	if apiVxIndex != -1 && apiVxIndex+1 < len(parts) {
		tag := parts[apiVxIndex+1]
		if tag != "" && !strings.Contains(tag, "{") {
			return tag
		}
	}
	
	// Fallback: use the first non-empty segment that's not api or vX
	for _, part := range parts {
		if part != "" && part != "api" && !strings.HasPrefix(part, "v") {
			return part
		}
	}
	
	return ""
}

func main() {
	// Get router initialization function
	outputFile := os.Args[1]
	jsonFormat := os.Args[2] == "true"
	yamlFormat := os.Args[3] == "true"

	// Create OpenAPI info - this will be populated from command line args
	info := &openapi3.Info{
		Title:       %#v,
		Description: %#v,
		Version:     %#v,
	}

	// Add contact info if provided
	contactName := %#v
	contactEmail := %#v
	contactURL := %#v
	if contactName != "" || contactEmail != "" || contactURL != "" {
		info.Contact = &openapi3.Contact{
			Name:  contactName,
			Email: contactEmail,
			URL:   contactURL,
		}
	}

	// Add license info if provided
	license := %#v
	licenseURL := %#v
	if license != "" {
		info.License = &openapi3.License{
			Name: license,
			URL:  licenseURL,
		}
	}

	// Get servers from command line
	var servers []*openapi3.Server
	%s

	// Initialize the router
	router := %s.%s()

	// Create swagger generator
	swaggerGen := NewSwaggerGen(router, info, servers)

	// Extract all routes
	if err := swaggerGen.ExtractRoutes(); err != nil {
		fmt.Printf("Error extracting routes: %%v\n", err)
		os.Exit(1)
	}

	// Save the OpenAPI specification
	if jsonFormat {
		jsonFile := outputFile
		if filepath.Ext(jsonFile) == "" {
			jsonFile += ".json"
		}
		if err := swaggerGen.SaveJSON(jsonFile); err != nil {
			fmt.Printf("Error saving JSON: %%v\n", err)
			os.Exit(1)
		}
	}

	if yamlFormat {
		yamlFile := outputFile
		if filepath.Ext(yamlFile) == "" {
			yamlFile += ".yaml"
		} else if filepath.Ext(yamlFile) == ".json" {
			yamlFile = strings.TrimSuffix(yamlFile, ".json") + ".yaml"
		}
		if err := swaggerGen.SaveYAML(yamlFile); err != nil {
			fmt.Printf("Error saving YAML: %%v\n", err)
			os.Exit(1)
		}
	}
}
`

	// Generate server code
	serverCode := "// No servers defined"
	if len(servers) > 0 {
		serverCode = "// Add servers\n"
		for _, server := range servers {
			serverCode += fmt.Sprintf(`	servers = append(servers, &openapi3.Server{
		URL: %#v,
		Description: %#v,
	})
`, server.URL, server.Description)
		}
	}

	// Format the code with the provided values
	formattedCode := fmt.Sprintf(code,
		routerPkg,
		info.Title,
		info.Description,
		info.Version,
		info.Contact.Name,
		info.Contact.Email,
		info.Contact.URL,
		info.License.Name,
		info.License.URL,
		serverCode,
		routerPkg,
		routerFunc,
	)

	// Write the code to the file
	_, err = f.WriteString(formattedCode)
	return err
}

// buildAndRunGenerator builds and runs the generator
func buildAndRunGenerator(genFile, outputFile string, jsonFormat, yamlFormat bool) error {
	// Build the generator
	buildCmd := exec.Command("go", "build", "-o", genFile+".exe", genFile)
	buildCmd.Stderr = os.Stderr
	if err := buildCmd.Run(); err != nil {
		return fmt.Errorf("failed to build generator: %w", err)
	}
	defer os.Remove(genFile + ".exe")

	// Run the generator
	runCmd := exec.Command(genFile+".exe", outputFile, fmt.Sprintf("%t", jsonFormat), fmt.Sprintf("%t", yamlFormat))
	runCmd.Stderr = os.Stderr
	return runCmd.Run()
}

// generateSwaggerUI generates Swagger UI files
func generateSwaggerUI(outDir, specPath string) error {
	// Create directory if it doesn't exist
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return err
	}

	// Create index.html with Swagger UI
	indexPath := filepath.Join(outDir, "index.html")
	f, err := os.Create(indexPath)
	if err != nil {
		return err
	}
	defer f.Close()

	// Write Swagger UI HTML
	// Uses CDN for Swagger UI resources
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Swagger UI</title>
  <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@4.5.0/swagger-ui.css" />
  <link rel="icon" type="image/png" href="https://unpkg.com/swagger-ui-dist@4.5.0/favicon-32x32.png" sizes="32x32" />
  <style>
    html {
      box-sizing: border-box;
      overflow: -moz-scrollbars-vertical;
      overflow-y: scroll;
    }
    
    *,
    *:before,
    *:after {
      box-sizing: inherit;
    }
    
    body {
      margin: 0;
      background: #fafafa;
    }
  </style>
</head>

<body>
  <div id="swagger-ui"></div>

  <script src="https://unpkg.com/swagger-ui-dist@4.5.0/swagger-ui-bundle.js"></script>
  <script src="https://unpkg.com/swagger-ui-dist@4.5.0/swagger-ui-standalone-preset.js"></script>
  <script>
    window.onload = function() {
      // Begin Swagger UI call region
      const ui = SwaggerUIBundle({
        url: %q,
        dom_id: '#swagger-ui',
        deepLinking: true,
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIStandalonePreset
        ],
        plugins: [
          SwaggerUIBundle.plugins.DownloadUrl
        ],
        layout: "StandaloneLayout"
      });
      // End Swagger UI call region
      window.ui = ui;
    };
  </script>
</body>
</html>`, filepath.Base(specPath))

	_, err = f.WriteString(html)
	return err
}
