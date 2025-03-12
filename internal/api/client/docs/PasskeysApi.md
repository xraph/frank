# {{classname}}

All URIs are relative to *https://auth.example.com/api/v1*

Method | HTTP request | Description
------------- | ------------- | -------------
[**DeletePasskey**](PasskeysApi.md#DeletePasskey) | **Delete** /auth/passkeys/{id} | Delete passkey
[**GetUserPasskeys**](PasskeysApi.md#GetUserPasskeys) | **Get** /auth/passkeys | Get user passkeys
[**PasskeyLoginBegin**](PasskeysApi.md#PasskeyLoginBegin) | **Post** /auth/passkeys/login/begin | Begin passkey login
[**PasskeyLoginComplete**](PasskeysApi.md#PasskeyLoginComplete) | **Post** /auth/passkeys/login/complete | Complete passkey login
[**PasskeyRegisterBegin**](PasskeysApi.md#PasskeyRegisterBegin) | **Post** /auth/passkeys/register/begin | Begin passkey registration
[**PasskeyRegisterComplete**](PasskeysApi.md#PasskeyRegisterComplete) | **Post** /auth/passkeys/register/complete | Complete passkey registration
[**UpdatePasskey**](PasskeysApi.md#UpdatePasskey) | **Put** /auth/passkeys/{id} | Update passkey

# **DeletePasskey**
> DeletePasskey(ctx, id)
Delete passkey

Delete a passkey

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

# **GetUserPasskeys**
> InlineResponse20016 GetUserPasskeys(ctx, )
Get user passkeys

Get the list of passkeys for the current user

### Required Parameters
This endpoint does not need any parameter.

### Return type

[**InlineResponse20016**](inline_response_200_16.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **PasskeyLoginBegin**
> InlineResponse20014 PasskeyLoginBegin(ctx, optional)
Begin passkey login

Start the process of logging in with a passkey

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
 **optional** | ***PasskeysApiPasskeyLoginBeginOpts** | optional parameters | nil if no parameters

### Optional Parameters
Optional parameters are passed through a pointer to a PasskeysApiPasskeyLoginBeginOpts struct
Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **body** | [**optional.Interface of interface{}**](interface{}.md)|  | 

### Return type

[**InlineResponse20014**](inline_response_200_14.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **PasskeyLoginComplete**
> InlineResponse20015 PasskeyLoginComplete(ctx, body)
Complete passkey login

Complete the process of logging in with a passkey

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **body** | [**LoginCompleteBody**](LoginCompleteBody.md)|  | 

### Return type

[**InlineResponse20015**](inline_response_200_15.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **PasskeyRegisterBegin**
> InlineResponse20014 PasskeyRegisterBegin(ctx, optional)
Begin passkey registration

Start the process of registering a passkey

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
 **optional** | ***PasskeysApiPasskeyRegisterBeginOpts** | optional parameters | nil if no parameters

### Optional Parameters
Optional parameters are passed through a pointer to a PasskeysApiPasskeyRegisterBeginOpts struct
Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **body** | [**optional.Interface of RegisterBeginBody**](RegisterBeginBody.md)|  | 

### Return type

[**InlineResponse20014**](inline_response_200_14.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **PasskeyRegisterComplete**
> RegisteredPasskey PasskeyRegisterComplete(ctx, body)
Complete passkey registration

Complete the process of registering a passkey

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **body** | [**RegisterCompleteBody**](RegisterCompleteBody.md)|  | 

### Return type

[**RegisteredPasskey**](RegisteredPasskey.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **UpdatePasskey**
> InlineResponse20017 UpdatePasskey(ctx, body, id)
Update passkey

Update a passkey's name

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **body** | [**PasskeysIdBody**](PasskeysIdBody.md)|  | 
  **id** | **string**|  | 

### Return type

[**InlineResponse20017**](inline_response_200_17.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

