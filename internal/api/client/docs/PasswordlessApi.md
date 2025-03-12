# {{classname}}

All URIs are relative to *https://auth.example.com/api/v1*

Method | HTTP request | Description
------------- | ------------- | -------------
[**GenerateMagicLink**](PasswordlessApi.md#GenerateMagicLink) | **Post** /auth/passwordless/magic-link | Generate magic link
[**GetPasswordlessMethods**](PasswordlessApi.md#GetPasswordlessMethods) | **Get** /auth/passwordless/methods | Get passwordless methods
[**PasswordlessEmail**](PasswordlessApi.md#PasswordlessEmail) | **Post** /auth/passwordless/email | Passwordless email login
[**PasswordlessSMS**](PasswordlessApi.md#PasswordlessSMS) | **Post** /auth/passwordless/sms | Passwordless SMS login
[**PasswordlessVerify**](PasswordlessApi.md#PasswordlessVerify) | **Post** /auth/passwordless/verify | Verify passwordless login

# **GenerateMagicLink**
> InlineResponse2008 GenerateMagicLink(ctx, body)
Generate magic link

Generate a magic link for a user

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **body** | [**PasswordlessMagiclinkBody**](PasswordlessMagiclinkBody.md)|  | 

### Return type

[**InlineResponse2008**](inline_response_200_8.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **GetPasswordlessMethods**
> InlineResponse2007 GetPasswordlessMethods(ctx, )
Get passwordless methods

Get available passwordless authentication methods

### Required Parameters
This endpoint does not need any parameter.

### Return type

[**InlineResponse2007**](inline_response_200_7.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **PasswordlessEmail**
> InlineResponse2004 PasswordlessEmail(ctx, body)
Passwordless email login

Request a magic link login for an email address

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **body** | [**PasswordlessEmailBody**](PasswordlessEmailBody.md)|  | 

### Return type

[**InlineResponse2004**](inline_response_200_4.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **PasswordlessSMS**
> InlineResponse2005 PasswordlessSMS(ctx, body)
Passwordless SMS login

Request an SMS code login for a phone number

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **body** | [**PasswordlessSmsBody**](PasswordlessSmsBody.md)|  | 

### Return type

[**InlineResponse2005**](inline_response_200_5.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **PasswordlessVerify**
> InlineResponse2006 PasswordlessVerify(ctx, body)
Verify passwordless login

Verify a passwordless login with token or code

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **body** | [**PasswordlessVerifyBody**](PasswordlessVerifyBody.md)|  | 

### Return type

[**InlineResponse2006**](inline_response_200_6.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

