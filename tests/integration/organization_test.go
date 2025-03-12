// tests/integration/organization_test.go
package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/internal/handlers"
	"github.com/juicycleff/frank/internal/middleware"
	"github.com/juicycleff/frank/internal/organization"
	"github.com/juicycleff/frank/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateOrganization(t *testing.T) {
	// Setup test dependencies
	cfg := setupTestConfig()
	ctx := context.Background()
	client := setupTestDatabase(t)
	defer client.Close()
	logger := logging.GetLogger()

	// Create a test user for ownership
	testUser, err := client.User.Create().
		SetEmail("orgtest@example.com").
		// SetPassword("password"). // Not relevant for this test
		SetFirstName("Org").
		SetLastName("Test").
		Save(ctx)
	require.NoError(t, err)

	// Setup organization service and handler
	orgRepo := organization.NewEntRepository(client)
	orgService := organization.NewService(orgRepo, cfg, logger)
	orgHandler := handlers.NewOrganizationHandler(orgService, cfg, logger)

	// Create test request
	orgData := map[string]interface{}{
		"name":     "Test Organization",
		"slug":     "test-org",
		"domain":   "test-org.com",
		"logo_url": "https://test-org.com/logo.png",
		"plan":     "enterprise",
		"features": []string{"sso", "mfa", "audit-logs"},
	}
	jsonData, err := json.Marshal(orgData)
	require.NoError(t, err)

	req, err := http.NewRequest("POST", "/api/v1/organizations", bytes.NewBuffer(jsonData))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	// Set user ID in request context to simulate authenticated user
	ctx = context.WithValue(ctx, middleware.UserIDKey, testUser.ID)
	req = req.WithContext(ctx)

	// Execute request
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(orgHandler.CreateOrganization)
	handler.ServeHTTP(rr, req)

	// Check response
	assert.Equal(t, http.StatusCreated, rr.Code)

	// Parse response
	var orgResponse map[string]interface{}
	err = json.Unmarshal(rr.Body.Bytes(), &orgResponse)
	require.NoError(t, err)

	// Validate organization was created
	assert.NotNil(t, orgResponse["id"])
	assert.Equal(t, "Test Organization", orgResponse["name"])
	assert.Equal(t, "test-org", orgResponse["slug"])
	assert.Equal(t, "test-org.com", orgResponse["domain"])
	assert.Equal(t, "enterprise", orgResponse["plan"])

	// Verify the organization exists in the database
	orgID := orgResponse["id"].(string)
	org, err := client.Organization.Get(ctx, orgID)
	require.NoError(t, err)
	assert.Equal(t, "Test Organization", org.Name)
}

func TestListOrganizations(t *testing.T) {
	// Setup test dependencies
	cfg := setupTestConfig()
	ctx := context.Background()
	client := setupTestDatabase(t)
	defer client.Close()
	logger := logging.GetLogger()

	// Create a test user
	testUser, err := client.User.Create().
		SetEmail("listorgtest@example.com").
		SetPassword("password").
		SetFirstName("List").
		SetLastName("Org").
		Save(ctx)
	require.NoError(t, err)

	// Create test organizations
	_, err = client.Organization.Create().
		SetName("Test Org 1").
		SetSlug("test-org-1").
		SetU(testUser.ID).
		SetActive(true).
		Save(ctx)
	require.NoError(t, err)

	_, err = client.Organization.Create().
		SetName("Test Org 2").
		SetSlug("test-org-2").
		SetOwnerID(testUser.ID).
		SetActive(true).
		Save(ctx)
	require.NoError(t, err)

	// Setup organization service and handler
	orgRepo := organization.NewEntRepository(client)
	orgService := organization.NewService(orgRepo, cfg, logger)
	orgHandler := handlers.NewOrganizationHandler(orgService, cfg, logger)

	// Create test request
	req, err := http.NewRequest("GET", "/api/v1/organizations", nil)
	require.NoError(t, err)

	// Execute request
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(orgHandler.ListOrganizations)
	handler.ServeHTTP(rr, req)

	// Check response
	assert.Equal(t, http.StatusOK, rr.Code)

	// Parse response
	var listResponse map[string]interface{}
	err = json.Unmarshal(rr.Body.Bytes(), &listResponse)
	require.NoError(t, err)

	// Validate response
	orgs, ok := listResponse["data"].([]interface{})
	require.True(t, ok)
	assert.Len(t, orgs, 2) // Should have both organizations

	// Check pagination info
	pagination, ok := listResponse["pagination"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, float64(0), pagination["offset"])
	assert.Equal(t, float64(20), pagination["limit"]) // Default limit
	assert.Equal(t, float64(2), pagination["total"])
}

func TestGetOrganization(t *testing.T) {
	// Setup test dependencies
	cfg := setupTestConfig()
	ctx := context.Background()
	client := setupTestDatabase(t)
	defer client.Close()
	logger := logging.GetLogger()

	// Create a test user
	testUser, err := client.User.Create().
		SetEmail("getorgtest@example.com").
		SetPassword("password").
		SetFirstName("Get").
		SetLastName("Org").
		Save(ctx)
	require.NoError(t, err)

	// Create test organization
	testOrg, err := client.Organization.Create().
		SetName("Get Org Test").
		SetSlug("get-org-test").
		SetOwnerID(testUser.ID).
		SetActive(true).
		Save(ctx)
	require.NoError(t, err)

	// Setup organization service and handler
	orgRepo := organization.NewEntRepository(client)
	orgService := organization.NewService(orgRepo, cfg, logger)
	orgHandler := handlers.NewOrganizationHandler(orgService, cfg, logger)

	// Create test request
	req, err := http.NewRequest("GET", "/api/v1/organizations/"+testOrg.ID, nil)
	require.NoError(t, err)

	// Execute request
	rr := httptest.NewRecorder()

	// Add URL path parameter to context
	req = addPathParam(req, "id", testOrg.ID)

	handler := http.HandlerFunc(orgHandler.GetOrganization)
	handler.ServeHTTP(rr, req)

	// Check response
	assert.Equal(t, http.StatusOK, rr.Code)

	// Parse response
	var orgResponse map[string]interface{}
	err = json.Unmarshal(rr.Body.Bytes(), &orgResponse)
	require.NoError(t, err)

	// Validate organization data
	assert.Equal(t, testOrg.ID, orgResponse["id"])
	assert.Equal(t, "Get Org Test", orgResponse["name"])
	assert.Equal(t, "get-org-test", orgResponse["slug"])
	assert.Equal(t, testUser.ID, orgResponse["owner_id"])
}

func TestUpdateOrganization(t *testing.T) {
	// Setup test dependencies
	cfg := setupTestConfig()
	ctx := context.Background()
	client := setupTestDatabase(t)
	defer client.Close()
	logger := logging.GetLogger()

	// Create a test user
	testUser, err := client.User.Create().
		SetEmail("updateorgtest@example.com").
		SetPassword("password").
		SetFirstName("Update").
		SetLastName("Org").
		Save(ctx)
	require.NoError(t, err)

	// Create test organization
	testOrg, err := client.Organization.Create().
		SetName("Original Name").
		SetSlug("original-slug").
		SetOwnerID(testUser.ID).
		SetActive(true).
		Save(ctx)
	require.NoError(t, err)

	// Setup organization service and handler
	orgRepo := organization.NewRepository(client)
	orgService := organization.NewService(orgRepo, cfg, logger)
	orgHandler := handlers.NewOrganizationHandler(orgService, cfg, logger)

	// Create update request
	updatedName := "Updated Name"
	updateData := map[string]interface{}{
		"name": updatedName,
		"plan": "premium",
	}
	jsonData, err := json.Marshal(updateData)
	require.NoError(t, err)

	req, err := http.NewRequest("PUT", "/api/v1/organizations/"+testOrg.ID, bytes.NewBuffer(jsonData))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	// Add URL path parameter to context
	req = addPathParam(req, "id", testOrg.ID)

	// Execute request
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(orgHandler.UpdateOrganization)
	handler.ServeHTTP(rr, req)

	// Check response
	assert.Equal(t, http.StatusOK, rr.Code)

	// Parse response
	var orgResponse map[string]interface{}
	err = json.Unmarshal(rr.Body.Bytes(), &orgResponse)
	require.NoError(t, err)

	// Validate organization was updated
	assert.Equal(t, updatedName, orgResponse["name"])
	assert.Equal(t, "premium", orgResponse["plan"])

	// Verify the update in the database
	updatedOrg, err := client.Organization.Get(ctx, testOrg.ID)
	require.NoError(t, err)
	assert.Equal(t, updatedName, updatedOrg.Name)
	assert.Equal(t, "premium", updatedOrg.Plan)
}

func TestManageOrganizationFeatures(t *testing.T) {
	// Setup test dependencies
	cfg := setupTestConfig()
	ctx := context.Background()
	client := setupTestDatabase(t)
	defer client.Close()
	logger := logging.GetLogger()

	// // Create a test user
	// testUser, err := client.User.Create().
	// 	SetEmail("featuretest@example.com").
	// 	// SetPassword("password").
	// 	SetFirstName("Feature").
	// 	SetLastName("Test").
	// 	Save(ctx)
	// require.NoError(t, err)

	// Create test organization
	testOrg, err := client.Organization.Create().
		SetName("Feature Test Org").
		SetSlug("feature-test-org").
		// SetOwnerID(testUser.ID).
		SetActive(true).
		Save(ctx)
	require.NoError(t, err)

	// Setup organization service and handler
	orgRepo := organization.NewRepository(client)
	orgService := organization.NewService(orgRepo, logger)
	orgHandler := handlers.NewOrganizationHandler(orgService, cfg, logger)

	// Step 1: Enable a feature
	featureKey := "sso"
	enableData := map[string]interface{}{
		"feature_key": featureKey,
		"settings": map[string]interface{}{
			"allowed_domains": []string{"example.com"},
		},
	}
	jsonData, err := json.Marshal(enableData)
	require.NoError(t, err)

	req, err := http.NewRequest("POST", "/api/v1/organizations/"+testOrg.ID+"/features", bytes.NewBuffer(jsonData))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	// Add URL path parameter to context
	req = addPathParam(req, "id", testOrg.ID)

	// Execute request
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(orgHandler.EnableOrganizationFeature)
	handler.ServeHTTP(rr, req)

	// Check response
	assert.Equal(t, http.StatusOK, rr.Code)

	// Step 2: List features to confirm it was added
	req, err = http.NewRequest("GET", "/api/v1/organizations/"+testOrg.ID+"/features", nil)
	require.NoError(t, err)

	// Add URL path parameter to context
	req = addPathParam(req, "id", testOrg.ID)

	// Execute request
	rr = httptest.NewRecorder()
	handler = http.HandlerFunc(orgHandler.ListOrganizationFeatures)
	handler.ServeHTTP(rr, req)

	// Check response
	assert.Equal(t, http.StatusOK, rr.Code)

	// Parse response
	var featuresResponse map[string]interface{}
	err = json.Unmarshal(rr.Body.Bytes(), &featuresResponse)
	require.NoError(t, err)

	// Validate features
	features, ok := featuresResponse["data"].([]interface{})
	require.True(t, ok)

	// Find the feature we just enabled
	var foundFeature bool
	for _, f := range features {
		feature := f.(map[string]interface{})
		if feature["key"] == featureKey {
			foundFeature = true
			assert.True(t, feature["enabled"].(bool))
			break
		}
	}
	assert.True(t, foundFeature, "Feature should be found in the response")

	// Step 3: Disable the feature
	req, err = http.NewRequest("DELETE", "/api/v1/organizations/"+testOrg.ID+"/features/"+featureKey, nil)
	require.NoError(t, err)

	// Add URL path parameters to context
	req = addPathParam(req, "id", testOrg.ID)
	req = addPathParam(req, "featureKey", featureKey)

	// Execute request
	rr = httptest.NewRecorder()
	handler = http.HandlerFunc(orgHandler.DisableOrganizationFeature)
	handler.ServeHTTP(rr, req)

	// Check response
	assert.Equal(t, http.StatusNoContent, rr.Code)
}

// Helper function to add URL path parameters to request context
func addPathParam(r *http.Request, key, value string) *http.Request {
	ctx := context.WithValue(r.Context(), key, value)
	return r.WithContext(ctx)
}
