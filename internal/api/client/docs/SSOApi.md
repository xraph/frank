# {{classname}}

All URIs are relative to *https://auth.example.com/api/v1*

Method | HTTP request | Description
------------- | ------------- | -------------
[**SsoProviderAuth**](SSOApi.md#SsoProviderAuth) | **Get** /auth/sso/providers/{provider} | Authenticate with SSO provider
[**SsoProviderCallback**](SSOApi.md#SsoProviderCallback) | **Get** /auth/sso/callback/{provider} | SSO callback
[**SsoProvidersList**](SSOApi.md#SsoProvidersList) | **Get** /auth/sso/providers | List SSO providers

# **SsoProviderAuth**
> SsoProviderAuth(ctx, provider, optional)
Authenticate with SSO provider

Start SSO authentication with a provider

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **provider** | **string**|  | 
 **optional** | ***SSOApiSsoProviderAuthOpts** | optional parameters | nil if no parameters

### Optional Parameters
Optional parameters are passed through a pointer to a SSOApiSsoProviderAuthOpts struct
Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **redirectUri** | **optional.String**|  | 

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **SsoProviderCallback**
> InlineResponse20019 SsoProviderCallback(ctx, provider, optional)
SSO callback

Handle SSO callback from a provider

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **provider** | **string**|  | 
 **optional** | ***SSOApiSsoProviderCallbackOpts** | optional parameters | nil if no parameters

### Optional Parameters
Optional parameters are passed through a pointer to a SSOApiSsoProviderCallbackOpts struct
Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **code** | **optional.String**|  | 
 **sAMLResponse** | **optional.String**|  | 
 **state** | **optional.String**|  | 

### Return type

[**InlineResponse20019**](inline_response_200_19.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **SsoProvidersList**
> InlineResponse20020 SsoProvidersList(ctx, optional)
List SSO providers

Get the list of available SSO providers

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
 **optional** | ***SSOApiSsoProvidersListOpts** | optional parameters | nil if no parameters

### Optional Parameters
Optional parameters are passed through a pointer to a SSOApiSsoProvidersListOpts struct
Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **organizationId** | **optional.String**|  | 

### Return type

[**InlineResponse20020**](inline_response_200_20.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

