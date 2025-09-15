package routes

import (
	"fmt"
	"net/http"

	"github.com/MarceloPetrucio/go-scalar-api-reference"
	customMiddleware "github.com/xraph/frank/internal/middleware"
	"github.com/xraph/frank/pkg/logging"
)

// setupDocsRoutes configures modern API documentation routes
func (router *Router) setupDocsRoutes() {
	if !router.mountOpts.IncludeRoutes.Docs || router.mountOpts.ExcludeRoutes.Docs {
		return
	}

	router.logger.Info("Setting up API documentation routes")

	// Get the OpenAPI specification URL
	openAPIPath := "/openapi.json"
	docsPath := "/docs"
	indexPath := "/"
	if router.mountOpts.BasePath != "" {
		indexPath = router.mountOpts.BasePath
		docsPath = router.mountOpts.BasePath + "/docs"
		openAPIPath = router.mountOpts.BasePath + "/openapi.json"
	}

	openAPIURL := openAPIPath
	if router.di.Config().Server.BaseURL != "" {
		openAPIURL = fmt.Sprintf("http://%s/%s", router.di.Config().GetServerAddress(), openAPIPath)
	}

	// Apply CSP middleware to all docs routes
	docsMiddleware := customMiddleware.DocsCORSMiddleware(openAPIURL)

	// Scalar API Documentation (Modern, beautiful UI)
	router.router.With(docsMiddleware).Get(docsPath+"/scalar", func(w http.ResponseWriter, r *http.Request) {
		scalarHTML, err := scalar.ApiReferenceHTML(&scalar.Options{
			SpecURL: openAPIURL,
			CustomOptions: scalar.CustomOptions{
				PageTitle: "Frank Auth API Documentation",
			},
			DarkMode: true,
			Layout:   scalar.LayoutModern,
		})
		if err != nil {
			router.logger.Error("Failed to generate Scalar documentation", logging.Error(err))
			http.Error(w, "Failed to generate documentation", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(scalarHTML))
	})

	// Redoc Documentation (Clean, responsive)
	router.router.With(docsMiddleware).Get(docsPath+"/redoc", func(w http.ResponseWriter, r *http.Request) {
		redocHTML := `<!DOCTYPE html>
<html>
<head>
	<title>Frank Auth API Documentation - ReDoc</title>
	<meta charset="utf-8"/>
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<link href="https://fonts.googleapis.com/css?family=Montserrat:300,400,700|Roboto:300,400,700" rel="stylesheet">
	<style>
		body { margin: 0; padding: 0; }
	</style>
</head>
<body>
	<redoc spec-url="` + openAPIPath + `"></redoc>
	<script src="https://cdn.redoc.ly/redoc/latest/bundles/redoc.standalone.js"></script>
</body>
</html>`

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(redocHTML))
	})

	// Swagger UI Documentation (Classic)
	router.router.With(docsMiddleware).Get(docsPath+"/swagger", func(w http.ResponseWriter, r *http.Request) {
		swaggerHTML := `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<title>Frank Auth API Documentation - Swagger UI</title>
	<link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5.10.5/swagger-ui.css" />
	<style>
		html { box-sizing: border-box; overflow: -moz-scrollbars-vertical; overflow-y: scroll; }
		*, *:before, *:after { box-sizing: inherit; }
		body { margin:0; background: #fafafa; }
	</style>
</head>
<body>
	<div id="swagger-ui"></div>
	<script src="https://unpkg.com/swagger-ui-dist@5.10.5/swagger-ui-bundle.js"></script>
	<script src="https://unpkg.com/swagger-ui-dist@5.10.5/swagger-ui-standalone-preset.js"></script>
	<script>
		window.onload = function() {
			const ui = SwaggerUIBundle({
				url: '` + openAPIPath + `',
				dom_id: '#swagger-ui',
				deepLinking: true,
				presets: [
					SwaggerUIBundle.presets.apis,
					SwaggerUIStandalonePreset
				],
				plugins: [
					SwaggerUIBundle.plugins.DownloadUrl
				],
				layout: "StandaloneLayout",
				theme: "dark"
			});
		};
	</script>
</body>
</html>`

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(swaggerHTML))
	})

	// RapiDoc Documentation (Fast, lightweight)
	router.router.With(docsMiddleware).Get(docsPath+"/rapidoc", func(w http.ResponseWriter, r *http.Request) {
		rapidocHTML := `<!doctype html>
<html>
<head>
	<meta charset="utf-8">
	<title>Frank Auth API Documentation - RapiDoc</title>
	<script type="module" src="https://unpkg.com/rapidoc/dist/rapidoc-min.js"></script>
</head>
<body>
	<rapi-doc 
		spec-url="` + openAPIPath + `"
		theme="dark"
		render-style="focused"
		nav-bg-color="#1f2937"
		primary-color="#3b82f6"
		secondary-color="#64748b"
		bg-color="#0f172a"
		text-color="#f1f5f9"
		header-color="#f1f5f9"
		nav-text-color="#f1f5f9"
		nav-hover-bg-color="#374151"
		nav-hover-text-color="#ffffff"
		nav-accent-color="#3b82f6"
		show-header="true"
		show-info="true"
		allow-authentication="true"
		allow-server-selection="true"
		allow-api-list-style-selection="true"
		show-components="true"
		sort-tags="true"
		goto-path=""
		fill-request-fields-with-example="true"
		persist-auth="true"
		> 
	</rapi-doc>
</body> 
</html>`

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(rapidocHTML))
	})

	// Elements by Stoplight (Modern, component-based)
	router.router.With(docsMiddleware).Get(docsPath+"/elements", func(w http.ResponseWriter, r *http.Request) {
		elementsHTML := `<!doctype html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
	<title>Frank Auth API Documentation - Elements</title>
	<script src="https://unpkg.com/@stoplight/elements/web-components.min.js"></script>
	<link rel="stylesheet" href="https://unpkg.com/@stoplight/elements/styles.min.css">
	<style>
		body { height: 100vh; overflow: hidden; margin: 0; }
	</style>
</head>
<body>
	<elements-api
		apiDescriptionUrl="` + openAPIPath + `"
		router="hash"
		layout="responsive"
		tryItCredentialsPolicy="include"
	/>
</body>
</html>`

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(elementsHTML))
	})

	// Postman Documentation (API Testing & Collaboration)
	router.router.With(docsMiddleware).Get(docsPath+"/postman", func(w http.ResponseWriter, r *http.Request) {
		postmanHTML := `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Frank Auth API Documentation - Postman</title>
	<style>
		* { margin: 0; padding: 0; box-sizing: border-box; }
		body {
			font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
			background: #f6f8fa; min-height: 100vh; padding: 2rem;
		}
		.container {
			max-width: 800px; margin: 0 auto; background: white; border-radius: 12px;
			padding: 3rem; box-shadow: 0 4px 16px rgba(0,0,0,0.1);
		}
		h1 { color: #ff6c37; margin-bottom: 1rem; font-size: 2.5rem; }
		.subtitle { color: #6b7280; margin-bottom: 2rem; font-size: 1.1rem; }
		.action-grid { display: grid; gap: 1.5rem; margin-bottom: 2rem; }
		.action-card {
			background: #f9fafb; border: 2px solid #e5e7eb; border-radius: 8px; padding: 1.5rem;
			transition: all 0.3s ease; cursor: pointer;
		}
		.action-card:hover { border-color: #ff6c37; transform: translateY(-2px); }
		.action-title { font-size: 1.2rem; font-weight: 600; color: #374151; margin-bottom: 0.5rem; }
		.action-desc { color: #6b7280; margin-bottom: 1rem; }
		.btn {
			background: #ff6c37; color: white; padding: 0.75rem 1.5rem; border: none;
			border-radius: 6px; text-decoration: none; display: inline-block; font-weight: 500;
			transition: background 0.3s ease;
		}
		.btn:hover { background: #e55a2b; }
		.btn-secondary {
			background: #374151; color: white; padding: 0.5rem 1rem; border: none;
			border-radius: 4px; text-decoration: none; display: inline-block; font-weight: 500;
			margin-left: 0.5rem;
		}
		.btn-secondary:hover { background: #4b5563; }
		.code-block {
			background: #1f2937; color: #f9fafb; padding: 1rem; border-radius: 6px;
			font-family: 'Monaco', 'Menlo', monospace; font-size: 0.9rem; overflow-x: auto;
			margin-top: 1rem;
		}
	</style>
</head>
<body>
	<div class="container">
		<h1>🚀 Postman Integration</h1>
		<p class="subtitle">Import and test the Frank Auth API directly in Postman</p>
		
		<div class="action-grid">
			<div class="action-card">
				<div class="action-title">Import OpenAPI to Postman</div>
				<div class="action-desc">Use the OpenAPI specification URL to automatically generate a Postman collection</div>
				<a href="https://web.postman.co/import-api?type=openapi&url=` + openAPIURL + `" target="_blank" class="btn">
					Import to Postman
				</a>
				<a href="` + openAPIURL + `" target="_blank" class="btn-secondary">View OpenAPI Spec</a>
			</div>
			
			<div class="action-card">
				<div class="action-title">Manual Import Instructions</div>
				<div class="action-desc">Steps to manually import the API specification into Postman</div>
				<div class="code-block">
1. Open Postman Desktop/Web App
2. Click "Import" button
3. Select "Link" tab
4. Paste: ` + openAPIURL + `
5. Click "Continue" and then "Import"</div>
			</div>
			
			<div class="action-card">
				<div class="action-title">Environment Setup</div>
				<div class="action-desc">Configure Postman environment variables for testing</div>
				<div class="code-block">
Base URL: ` + fmt.Sprintf("http://%s", router.di.Config().GetServerAddress()) + `
API Key: {{your_api_key}}
Tenant ID: {{your_tenant_id}}</div>
			</div>
		</div>
		
		<p style="text-align: center; color: #6b7280; font-size: 0.9rem;">
			<strong>Note:</strong> You'll need Postman Desktop or Web App to import and test the collection.
		</p>
	</div>
</body>
</html>`

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(postmanHTML))
	})

	// ApiDog Documentation (API Design & Testing)
	router.router.With(docsMiddleware).Get(docsPath+"/apidog", func(w http.ResponseWriter, r *http.Request) {
		apidogHTML := `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Frank Auth API Documentation - ApiDog</title>
	<style>
		* { margin: 0; padding: 0; box-sizing: border-box; }
		body {
			font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
			background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
			min-height: 100vh; padding: 2rem;
		}
		.container {
			max-width: 800px; margin: 0 auto; background: white; border-radius: 16px;
			padding: 3rem; box-shadow: 0 8px 32px rgba(0,0,0,0.1);
		}
		h1 { color: #1a365d; margin-bottom: 1rem; font-size: 2.5rem; }
		.subtitle { color: #718096; margin-bottom: 2rem; font-size: 1.1rem; }
		.feature-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }
		.feature-card {
			background: #f7fafc; border-radius: 12px; padding: 1.5rem;
			border-left: 4px solid #4299e1; transition: transform 0.3s ease;
		}
		.feature-card:hover { transform: translateY(-3px); }
		.feature-title { font-size: 1.1rem; font-weight: 600; color: #2d3748; margin-bottom: 0.5rem; }
		.feature-desc { color: #718096; font-size: 0.9rem; line-height: 1.5; }
		.btn {
			background: #4299e1; color: white; padding: 1rem 2rem; border: none;
			border-radius: 8px; text-decoration: none; display: inline-block; font-weight: 600;
			font-size: 1rem; transition: all 0.3s ease; margin-right: 1rem;
		}
		.btn:hover { background: #3182ce; transform: translateY(-2px); }
		.btn-outline {
			background: transparent; color: #4299e1; border: 2px solid #4299e1;
			padding: 0.875rem 1.875rem;
		}
		.btn-outline:hover { background: #4299e1; color: white; }
		.import-section {
			background: #edf2f7; border-radius: 12px; padding: 2rem; margin-top: 2rem;
		}
		.code-snippet {
			background: #2d3748; color: #e2e8f0; padding: 1rem; border-radius: 8px;
			font-family: 'Monaco', 'Menlo', monospace; font-size: 0.9rem; margin-top: 1rem;
			overflow-x: auto;
		}
	</style>
</head>
<body>
	<div class="container">
		<h1>🐕 ApiDog Integration</h1>
		<p class="subtitle">Design, test, and document your API with ApiDog's all-in-one platform</p>
		
		<div class="feature-grid">
			<div class="feature-card">
				<div class="feature-title">🎨 API Design</div>
				<div class="feature-desc">Visual API designer with OpenAPI 3.0 support and real-time collaboration</div>
			</div>
			<div class="feature-card">
				<div class="feature-title">🧪 Testing Suite</div>
				<div class="feature-desc">Automated testing with assertions, environments, and CI/CD integration</div>
			</div>
			<div class="feature-card">
				<div class="feature-title">📚 Documentation</div>
				<div class="feature-desc">Beautiful, interactive API documentation generated from your OpenAPI spec</div>
			</div>
			<div class="feature-card">
				<div class="feature-title">🔄 Mock Server</div>
				<div class="feature-desc">Dynamic mock server for frontend development and testing</div>
			</div>
		</div>
		
		<div style="text-align: center; margin: 2rem 0;">
			<a href="https://apidog.com/apidoc/shared-import?url=` + openAPIURL + `" target="_blank" class="btn">
				Import to ApiDog
			</a>
			<a href="https://apidog.com" target="_blank" class="btn btn-outline">
				Learn More
			</a>
		</div>
		
		<div class="import-section">
			<h3 style="margin-bottom: 1rem; color: #2d3748;">Manual Import Steps</h3>
			<p style="color: #4a5568; margin-bottom: 1rem;">Follow these steps to import the Frank Auth API into ApiDog:</p>
			<div class="code-snippet">
1. Sign up/Login to ApiDog (https://apidog.com)
2. Create a new project or open existing one
3. Click "Import" → "From URL"
4. Paste the OpenAPI URL: ` + openAPIURL + `
5. Configure import settings and click "Import"
6. OnStart designing, testing, and documenting!</div>
		</div>
		
		<p style="text-align: center; color: #718096; font-size: 0.9rem; margin-top: 2rem;">
			<strong>Pro Tip:</strong> ApiDog offers team collaboration features and integrates well with Git workflows.
		</p>
	</div>
</body>
</html>`

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(apidogHTML))
	})

	// Readme UI Documentation (Developer Hub)
	router.router.With(docsMiddleware).Get(docsPath+"/readme", func(w http.ResponseWriter, r *http.Request) {
		readmeHTML := `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Frank Auth API Documentation - ReadMe</title>
	<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
	<style>
		* { margin: 0; padding: 0; box-sizing: border-box; }
		body {
			font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
			background: #0f172a; color: #f1f5f9; min-height: 100vh;
		}
		.header {
			background: linear-gradient(135deg, #1e293b 0%, #334155 100%);
			padding: 2rem 0; text-align: center; border-bottom: 1px solid #334155;
		}
		.header h1 { font-size: 3rem; font-weight: 700; color: #60a5fa; margin-bottom: 0.5rem; }
		.header p { font-size: 1.2rem; color: #94a3b8; }
		.container { max-width: 1200px; margin: 0 auto; padding: 3rem 2rem; }
		.readme-embed {
			background: #1e293b; border-radius: 16px; padding: 2rem;
			border: 1px solid #334155; box-shadow: 0 8px 32px rgba(0,0,0,0.3);
		}
		.embed-header {
			display: flex; align-items: center; justify-content: space-between;
			margin-bottom: 2rem; padding-bottom: 1rem; border-bottom: 1px solid #334155;
		}
		.embed-title { font-size: 1.5rem; font-weight: 600; color: #f1f5f9; }
		.embed-badge {
			background: #60a5fa; color: #0f172a; padding: 0.5rem 1rem;
			border-radius: 20px; font-size: 0.9rem; font-weight: 500;
		}
		.api-explorer {
			background: #0f172a; border-radius: 12px; padding: 2rem;
			border: 1px solid #1e293b; margin-bottom: 2rem;
		}
		.explorer-title {
			font-size: 1.3rem; font-weight: 600; color: #60a5fa;
			margin-bottom: 1rem; display: flex; align-items: center;
		}
		.explorer-title::before {
			content: "🔍"; margin-right: 0.5rem; font-size: 1.5rem;
		}
		.endpoint-list {
			display: grid; gap: 1rem;
		}
		.endpoint {
			background: #1e293b; border-radius: 8px; padding: 1rem;
			border-left: 4px solid #60a5fa; transition: all 0.3s ease;
		}
		.endpoint:hover { background: #334155; transform: translateX(4px); }
		.endpoint-method {
			display: inline-block; padding: 0.25rem 0.75rem; border-radius: 4px;
			font-size: 0.8rem; font-weight: 600; margin-right: 1rem;
		}
		.get { background: #10b981; color: white; }
		.post { background: #3b82f6; color: white; }
		.put { background: #f59e0b; color: white; }
		.delete { background: #ef4444; color: white; }
		.endpoint-path { color: #e2e8f0; font-family: 'Monaco', monospace; }
		.endpoint-desc { color: #94a3b8; font-size: 0.9rem; margin-top: 0.5rem; }
		.cta-section {
			text-align: center; margin-top: 3rem; padding: 2rem;
			background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
			border-radius: 16px; border: 1px solid #334155;
		}
		.btn {
			background: #60a5fa; color: #0f172a; padding: 1rem 2rem;
			border: none; border-radius: 8px; text-decoration: none;
			display: inline-block; font-weight: 600; font-size: 1rem;
			transition: all 0.3s ease; margin: 0 0.5rem;
		}
		.btn:hover { background: #3b82f6; transform: translateY(-2px); }
		.btn-outline {
			background: transparent; color: #60a5fa; border: 2px solid #60a5fa;
		}
		.btn-outline:hover { background: #60a5fa; color: #0f172a; }
	</style>
</head>
<body>
	<div class="header">
		<h1>📖 ReadMe Integration</h1>
		<p>Beautiful developer documentation and API explorer</p>
	</div>
	
	<div class="container">
		<div class="readme-embed">
			<div class="embed-header">
				<div class="embed-title">Frank Auth API Explorer</div>
				<div class="embed-badge">Interactive Docs</div>
			</div>
			
			<div class="api-explorer">
				<div class="explorer-title">API Endpoints</div>
				<div class="endpoint-list">
					<div class="endpoint">
						<span class="endpoint-method post">POST</span>
						<span class="endpoint-path">/auth/login</span>
						<div class="endpoint-desc">Authenticate user and return JWT token</div>
					</div>
					<div class="endpoint">
						<span class="endpoint-method post">POST</span>
						<span class="endpoint-path">/auth/register</span>
						<div class="endpoint-desc">Register new user account</div>
					</div>
					<div class="endpoint">
						<span class="endpoint-method get">GET</span>
						<span class="endpoint-path">/auth/profile</span>
						<div class="endpoint-desc">Get authenticated user profile</div>
					</div>
					<div class="endpoint">
						<span class="endpoint-method post">POST</span>
						<span class="endpoint-path">/auth/refresh</span>
						<div class="endpoint-desc">Refresh JWT access token</div>
					</div>
					<div class="endpoint">
						<span class="endpoint-method post">POST</span>
						<span class="endpoint-path">/tenants</span>
						<div class="endpoint-desc">Create new tenant</div>
					</div>
					<div class="endpoint">
						<span class="endpoint-method get">GET</span>
						<span class="endpoint-path">/tenants/{id}</span>
						<div class="endpoint-desc">Get tenant information</div>
					</div>
				</div>
			</div>
			
			<div style="background: #0f172a; border-radius: 12px; padding: 2rem; border: 1px solid #1e293b;">
				<h3 style="color: #60a5fa; margin-bottom: 1rem;">🚀 Try it out</h3>
				<p style="color: #94a3b8; margin-bottom: 1.5rem;">
					Experience the full interactive documentation with live API testing, code examples in multiple languages, 
					and comprehensive guides.
				</p>
				<div style="background: #1e293b; padding: 1rem; border-radius: 8px; font-family: monospace; color: #e2e8f0;">
					curl -X GET "` + openAPIURL + `" \<br>
					&nbsp;&nbsp;-H "Accept: application/json"
				</div>
			</div>
		</div>
		
		<div class="cta-section">
			<h2 style="color: #f1f5f9; margin-bottom: 1rem;">Ready to explore?</h2>
			<p style="color: #94a3b8; margin-bottom: 2rem;">
				Get the full ReadMe experience with interactive testing, SDKs, and comprehensive documentation.
			</p>
			<a href="https://readme.com/import?url=` + openAPIURL + `" target="_blank" class="btn">
				Import to ReadMe
			</a>
			<a href="` + openAPIURL + `" target="_blank" class="btn btn-outline">
				View OpenAPI Spec
			</a>
		</div>
	</div>
</body>
</html>`

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(readmeHTML))
	})

	// Documentation index page with links to all documentation variants
	router.router.With(docsMiddleware).Get(docsPath, func(w http.ResponseWriter, r *http.Request) {
		indexHTML := `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Frank Auth API Documentation</title>
	<style>
		* { margin: 0; padding: 0; box-sizing: border-box; }
		body {
			font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
			background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
			min-height: 100vh; display: flex; align-items: center; justify-content: center;
		}
		.container {
			background: white; border-radius: 20px; padding: 3rem; box-shadow: 0 20px 40px rgba(0,0,0,0.1);
			max-width: 800px; text-align: center;
		}
		h1 { color: #2d3748; margin-bottom: 0.5rem; font-size: 2.5rem; font-weight: 700; }
		.subtitle { color: #718096; margin-bottom: 3rem; font-size: 1.1rem; }
		.docs-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.5rem; }
		.doc-card {
			background: #f7fafc; border-radius: 12px; padding: 2rem; transition: all 0.3s ease;
			border: 2px solid transparent; text-decoration: none; color: inherit;
		}
		.doc-card:hover {
			transform: translateY(-5px); box-shadow: 0 10px 25px rgba(0,0,0,0.1);
			border-color: #667eea;
		}
		.doc-title { font-size: 1.3rem; font-weight: 600; color: #2d3748; margin-bottom: 0.5rem; }
		.doc-description { color: #718096; font-size: 0.95rem; line-height: 1.5; }
		.badge { display: inline-block; background: #667eea; color: white; padding: 0.25rem 0.75rem;
			border-radius: 20px; font-size: 0.8rem; font-weight: 500; margin-top: 1rem; }
		.new { background: #48bb78; }
		.popular { background: #ed8936; }
		.footer { margin-top: 3rem; padding-top: 2rem; border-top: 1px solid #e2e8f0; color: #718096; }
	</style>
</head>
<body>
	<div class="container">
		<h1>🔐 Frank Auth API</h1>
		<p class="subtitle">Multi-tenant Authentication SaaS Platform Documentation</p>
		
		<div class="docs-grid">
			<a href="/docs/scalar" class="doc-card">
				<div class="doc-title">Scalar</div>
				<div class="doc-description">Modern, beautiful API documentation with interactive examples and dark mode support.</div>
				<span class="badge new">✨ Modern</span>
			</a>
			
			<a href="/docs/redoc" class="doc-card">
				<div class="doc-title">ReDoc</div>
				<div class="doc-description">Clean, responsive API documentation with three-panel layout and excellent mobile support.</div>
				<span class="badge popular">🔥 Popular</span>
			</a>
			
			<a href="/docs/swagger" class="doc-card">
				<div class="doc-title">Swagger UI</div>
				<div class="doc-description">The classic API documentation interface with built-in testing capabilities.</div>
				<span class="badge">📊 Classic</span>
			</a>
			
			<a href="/docs/rapidoc" class="doc-card">
				<div class="doc-title">RapiDoc</div>
				<div class="doc-description">Fast, lightweight API documentation with customizable themes and focused layout.</div>
				<span class="badge">⚡ Fast</span>
			</a>
			
			<a href="/docs/elements" class="doc-card">  
				<div class="doc-title">Elements</div>
				<div class="doc-description">Component-based API documentation by Stoplight with advanced features.</div>
				<span class="badge new">🎨 Advanced</span>
			</a>
			
			<a href="/docs/postman" class="doc-card">
				<div class="doc-title">Postman</div>
				<div class="doc-description">Import API to Postman for testing, collaboration, and collection management.</div>
				<span class="badge">🚀 Testing</span>
			</a>
			
			<a href="/docs/apidog" class="doc-card">
				<div class="doc-title">ApiDog</div>
				<div class="doc-description">All-in-one API platform for design, testing, documentation, and mock servers.</div>
				<span class="badge new">🐕 All-in-One</span>
			</a>
			
			<a href="/docs/readme" class="doc-card">
				<div class="doc-title">ReadMe</div>
				<div class="doc-description">Developer hub with interactive docs, guides, and beautiful API exploration.</div>
				<span class="badge new">📖 Hub</span>
			</a>
			
			<a href="` + openAPIURL + `" class="doc-card">
				<div class="doc-title">OpenAPI JSON</div>
				<div class="doc-description">Raw OpenAPI 3.0 specification for integration with other tools.</div>
				<span class="badge">🔧 Raw Data</span>
			</a>
		</div>
		
		<div class="footer">
			<p><strong>Features:</strong> Multi-tenant • Three-tier Users • OAuth2 • JWT • MFA • SSO • RBAC • Audit Logs</p>
		</div>
	</div>
</body>
</html>`

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(indexHTML))
	})

	// Default docs redirect
	router.router.Get(indexPath, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/docs", http.StatusTemporaryRedirect)
	})

	router.logger.Info("Frank API documentation routes configured",
		logging.String("docsPath", docsPath),
		logging.String("scalar", docsPath+"/scalar"),
		logging.String("redoc", docsPath+"/redoc"),
		logging.String("swagger", docsPath+"/swagger"),
		logging.String("rapidoc", docsPath+"/rapidoc"),
		logging.String("elements", docsPath+"/elements"),
		logging.String("postman", docsPath+"/postman"),
		logging.String("apidog", docsPath+"/apidog"),
		logging.String("readme", docsPath+"/readme"),
		logging.String("openapi", openAPIURL),
	)
}
