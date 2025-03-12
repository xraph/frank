# {{classname}}

All URIs are relative to *https://auth.example.com/api/v1*

Method | HTTP request | Description
------------- | ------------- | -------------
[**GetMFAMethods**](MFAApi.md#GetMFAMethods) | **Get** /auth/mfa/methods | Get MFA methods
[**MfaEnroll**](MFAApi.md#MfaEnroll) | **Post** /auth/mfa/enroll | Enroll in MFA
[**MfaUnenroll**](MFAApi.md#MfaUnenroll) | **Post** /auth/mfa/unenroll | Unenroll from MFA
[**MfaVerify**](MFAApi.md#MfaVerify) | **Post** /auth/mfa/verify | Verify MFA
[**SendMFACode**](MFAApi.md#SendMFACode) | **Post** /auth/mfa/send-code | Send MFA code

# **GetMFAMethods**
> InlineResponse20012 GetMFAMethods(ctx, )
Get MFA methods

Get enabled MFA methods for the current user

### Required Parameters
This endpoint does not need any parameter.

### Return type

[**InlineResponse20012**](inline_response_200_12.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **MfaEnroll**
> InlineResponse2009 MfaEnroll(ctx, body)
Enroll in MFA

Enroll in a multi-factor authentication method

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **body** | [**MfaEnrollBody**](MfaEnrollBody.md)|  | 

### Return type

[**InlineResponse2009**](inline_response_200_9.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **MfaUnenroll**
> InlineResponse20011 MfaUnenroll(ctx, body)
Unenroll from MFA

Unenroll from a multi-factor authentication method

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **body** | [**MfaUnenrollBody**](MfaUnenrollBody.md)|  | 

### Return type

[**InlineResponse20011**](inline_response_200_11.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **MfaVerify**
> InlineResponse20010 MfaVerify(ctx, body)
Verify MFA

Verify a multi-factor authentication code

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **body** | [**MfaVerifyBody**](MfaVerifyBody.md)|  | 

### Return type

[**InlineResponse20010**](inline_response_200_10.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **SendMFACode**
> InlineResponse20013 SendMFACode(ctx, body)
Send MFA code

Send a multi-factor authentication code

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **body** | [**MfaSendcodeBody**](MfaSendcodeBody.md)|  | 

### Return type

[**InlineResponse20013**](inline_response_200_13.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

