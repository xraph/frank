# {{classname}}

All URIs are relative to *https://auth.example.com/api/v1*

Method | HTTP request | Description
------------- | ------------- | -------------
[**DeleteUserSession**](SessionApi.md#DeleteUserSession) | **Delete** /users/me/sessions/{id} | Delete session
[**GetUserSessions**](SessionApi.md#GetUserSessions) | **Get** /users/me/sessions | Get user sessions

# **DeleteUserSession**
> DeleteUserSession(ctx, id)
Delete session

Delete a specific session for the current user

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **id** | **string**|  | 

### Return type

 (empty response body)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **GetUserSessions**
> InlineResponse20021 GetUserSessions(ctx, )
Get user sessions

Get the active sessions for the current user

### Required Parameters
This endpoint does not need any parameter.

### Return type

[**InlineResponse20021**](inline_response_200_21.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

