package activity

import (
	"context"
	"time"

	"github.com/juicycleff/frank/pkg/model"
	"github.com/rs/xid"
)

// ================================================
// Service Helper Functions
// ================================================

// Helper functions for common activity patterns

// RecordAPIKeyUsage - optimized for API key activities
func RecordAPIKeyUsage(activitySvc Service, ctx context.Context, keyID xid.ID, endpoint, method string, statusCode, responseTime int, ipAddress, userAgent string) error {
	return activitySvc.RecordAPIActivity(ctx, &APIActivityRecord{
		KeyID:        keyID,
		Endpoint:     endpoint,
		Method:       method,
		StatusCode:   statusCode,
		ResponseTime: responseTime,
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		Success:      statusCode >= 200 && statusCode < 300,
		Timestamp:    time.Now(),
	})
}

// RecordUserLogin - optimized for user login activities
func RecordUserLogin(activitySvc Service, ctx context.Context, userID xid.ID, orgID *xid.ID, success bool, ipAddress, userAgent string, errorMsg string) error {
	return activitySvc.RecordUserActivity(ctx, &UserActivityRecord{
		UserID:         userID,
		OrganizationID: orgID,
		Action:         "login",
		IPAddress:      ipAddress,
		UserAgent:      userAgent,
		Success:        success,
		Error:          errorMsg,
		Timestamp:      time.Now(),
	})
}

// RecordResourceCreation - generic resource creation activity
func RecordResourceCreation(activitySvc Service, ctx context.Context, resourceType model.ResourceType, resourceID, userID xid.ID, orgID *xid.ID) error {
	return activitySvc.RecordActivity(ctx, &ActivityRecord{
		ID:             xid.New(),
		ResourceType:   resourceType,
		ResourceID:     resourceID,
		UserID:         &userID,
		OrganizationID: orgID,
		Action:         "created",
		Category:       "admin",
		Source:         "web",
		Success:        true,
		Timestamp:      time.Now(),
		Count:          1,
	})
}

// RecordDataExport - for compliance tracking
func RecordDataExport(activitySvc Service, ctx context.Context, resourceType model.ResourceType, userID xid.ID, orgID *xid.ID, exportType string, recordCount int) error {
	return activitySvc.RecordActivity(ctx, &ActivityRecord{
		ID:             xid.New(),
		ResourceType:   resourceType,
		ResourceID:     userID, // User who performed export
		UserID:         &userID,
		OrganizationID: orgID,
		Action:         "data_export",
		Category:       "compliance",
		Source:         "web",
		Success:        true,
		Timestamp:      time.Now(),
		Count:          recordCount,
		Metadata: map[string]interface{}{
			"export_type":  exportType,
			"record_count": recordCount,
		},
		Tags: []string{"compliance", "data_export", "audit"},
	})
}
