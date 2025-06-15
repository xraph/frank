package activity

// // Usage example for different services:
//
// // API Key Service
// func (apiKeyService *service) recordAPIUsage(ctx context.Context, keyID xid.ID, endpoint, method string, statusCode int, responseTime int) error {
// 	return s.activityService.RecordAPIActivity(ctx, &APIActivityRecord{
// 		KeyID:        keyID,
// 		Endpoint:     endpoint,
// 		Method:       method,
// 		StatusCode:   statusCode,
// 		ResponseTime: responseTime,
// 		Success:      statusCode >= 200 && statusCode < 300,
// 		Timestamp:    time.Now(),
// 	})
// }
//
// // User Service
// func (userService *service) recordUserLogin(ctx context.Context, userID xid.ID, success bool, ipAddress string) error {
// 	return s.activityService.RecordUserActivity(ctx, &UserActivityRecord{
// 		UserID:    userID,
// 		Action:    "login",
// 		IPAddress: ipAddress,
// 		Success:   success,
// 		Timestamp: time.Now(),
// 	})
// }
//
// // Organization Service
// func (orgService *service) recordMemberAdded(ctx context.Context, orgID, newMemberID xid.ID) error {
// 	return s.activityService.RecordActivity(ctx, &ActivityRecord{
// 		ID:             xid.New(),
// 		ResourceType:   "organization",
// 		ResourceID:     orgID,
// 		Action:         "member_added",
// 		Category:       "admin",
// 		Success:        true,
// 		Timestamp:      time.Now(),
// 		Count:          1,
// 		Metadata: map[string]interface{}{
// 			"new_member_id": newMemberID.String(),
// 		},
// 	})
// }
