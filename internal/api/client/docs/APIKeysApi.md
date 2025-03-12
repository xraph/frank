# {{classname}}

All URIs are relative to *https://auth.example.com/api/v1*

Method | HTTP request | Description
------------- | ------------- | -------------
[**CreateAPIKey**](APIKeysApi.md#CreateAPIKey) | **Post** /api-keys | Create API key
[**DeleteAPIKey**](APIKeysApi.md#DeleteAPIKey) | **Delete** /api-keys/{id} | Delete API key
[**GetAPIKey**](APIKeysApi.md#GetAPIKey) | **Get** /api-keys/{id} | Get API key
[**ListAPIKeys**](APIKeysApi.md#ListAPIKeys) | **Get** /api-keys | List API keys
[**UpdateAPIKey**](APIKeysApi.md#UpdateAPIKey) | **Put** /api-keys/{id} | Update API key
[**ValidateAPIKey**](APIKeysApi.md#ValidateAPIKey) | **Post** /api-keys/validate | Validate API key

# **CreateAPIKey**
> ApiKeyWithKey CreateAPIKey(ctx, body)
Create API key

Create a new API key

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **body** | [**ApikeysBody**](ApikeysBody.md)|  | 

### Return type

[**ApiKeyWithKey**](APIKeyWithKeyResponse.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **DeleteAPIKey**
> DeleteAPIKey(ctx, id)
Delete API key

Delete a specific API key

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

# **GetAPIKey**
> ApiKey GetAPIKey(ctx, id)
Get API key

Get a specific API key

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **id** | **string**|  | 

### Return type

[**ApiKey**](APIKey.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ListAPIKeys**
> InlineResponse20028 ListAPIKeys(ctx, optional)
List API keys

List API keys with pagination

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
 **optional** | ***APIKeysApiListAPIKeysOpts** | optional parameters | nil if no parameters

### Optional Parameters
Optional parameters are passed through a pointer to a APIKeysApiListAPIKeysOpts struct
Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **offset** | **optional.Int32**|  | [default to 0]
 **limit** | **optional.Int32**|  | [default to 20]
 **type_** | **optional.String**|  | 

### Return type

[**InlineResponse20028**](inline_response_200_28.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **UpdateAPIKey**
> ApiKey UpdateAPIKey(ctx, body, id)
Update API key

Update a specific API key

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **body** | [**ApikeysIdBody**](ApikeysIdBody.md)|  | 
  **id** | **string**|  | 

### Return type

[**ApiKey**](APIKey.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ValidateAPIKey**
> ApiKey ValidateAPIKey(ctx, )
Validate API key

Validate an API key

### Required Parameters
This endpoint does not need any parameter.

### Return type

[**ApiKey**](APIKey.md)

### Authorization

[apiKeyAuth](../README.md#apiKeyAuth)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

