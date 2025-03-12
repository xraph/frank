# {{classname}}

All URIs are relative to *https://auth.example.com/api/v1*

Method | HTTP request | Description
------------- | ------------- | -------------
[**AuthorizeOAuth2**](OAuth2Api.md#AuthorizeOAuth2) | **Get** /oauth2/authorize | OAuth2 authorization endpoint
[**IntrospectOAuth2**](OAuth2Api.md#IntrospectOAuth2) | **Post** /oauth2/introspect | OAuth2 token introspection
[**JwksEndpoint**](OAuth2Api.md#JwksEndpoint) | **Get** /.well-known/jwks.json | JSON Web Key Set
[**OauthProviderAuth**](OAuth2Api.md#OauthProviderAuth) | **Get** /auth/oauth/providers/{provider} | Authenticate with OAuth provider
[**OauthProviderCallback**](OAuth2Api.md#OauthProviderCallback) | **Get** /auth/oauth/callback/{provider} | OAuth callback
[**OauthProvidersList**](OAuth2Api.md#OauthProvidersList) | **Get** /auth/oauth/providers | List OAuth providers
[**OidcConfiguration**](OAuth2Api.md#OidcConfiguration) | **Get** /.well-known/openid-configuration | OpenID Connect configuration
[**RevokeOAuth2**](OAuth2Api.md#RevokeOAuth2) | **Post** /oauth2/revoke | OAuth2 token revocation
[**TokenOAuth2**](OAuth2Api.md#TokenOAuth2) | **Post** /oauth2/token | OAuth2 token endpoint
[**UserInfoOAuth2**](OAuth2Api.md#UserInfoOAuth2) | **Get** /oauth2/userinfo | OpenID Connect userinfo endpoint

# **AuthorizeOAuth2**
> AuthorizeOAuth2(ctx, clientId, redirectUri, responseType, optional)
OAuth2 authorization endpoint

Initiates the OAuth2 authorization code flow

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **clientId** | **string**|  | 
  **redirectUri** | **string**|  | 
  **responseType** | **string**|  | 
 **optional** | ***OAuth2ApiAuthorizeOAuth2Opts** | optional parameters | nil if no parameters

### Optional Parameters
Optional parameters are passed through a pointer to a OAuth2ApiAuthorizeOAuth2Opts struct
Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------



 **scope** | **optional.String**|  | 
 **state** | **optional.String**|  | 
 **codeChallenge** | **optional.String**|  | 
 **codeChallengeMethod** | **optional.String**|  | 

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **IntrospectOAuth2**
> InlineResponse20031 IntrospectOAuth2(ctx, token, tokenTypeHint, clientId, clientSecret)
OAuth2 token introspection

Check if a token is valid and get information about it

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **token** | **string**|  | 
  **tokenTypeHint** | **string**|  | 
  **clientId** | **string**|  | 
  **clientSecret** | **string**|  | 

### Return type

[**InlineResponse20031**](inline_response_200_31.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/x-www-form-urlencoded
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **JwksEndpoint**
> InlineResponse20033 JwksEndpoint(ctx, )
JSON Web Key Set

Get the JSON Web Key Set for token verification

### Required Parameters
This endpoint does not need any parameter.

### Return type

[**InlineResponse20033**](inline_response_200_33.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **OauthProviderAuth**
> OauthProviderAuth(ctx, provider, optional)
Authenticate with OAuth provider

Start OAuth authentication with a provider

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **provider** | **string**|  | 
 **optional** | ***OAuth2ApiOauthProviderAuthOpts** | optional parameters | nil if no parameters

### Optional Parameters
Optional parameters are passed through a pointer to a OAuth2ApiOauthProviderAuthOpts struct
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

# **OauthProviderCallback**
> InlineResponse20019 OauthProviderCallback(ctx, provider, code, state)
OAuth callback

Handle OAuth callback from a provider

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **provider** | **string**|  | 
  **code** | **string**|  | 
  **state** | **string**|  | 

### Return type

[**InlineResponse20019**](inline_response_200_19.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **OauthProvidersList**
> InlineResponse20018 OauthProvidersList(ctx, )
List OAuth providers

Get the list of available OAuth providers

### Required Parameters
This endpoint does not need any parameter.

### Return type

[**InlineResponse20018**](inline_response_200_18.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **OidcConfiguration**
> InlineResponse20032 OidcConfiguration(ctx, )
OpenID Connect configuration

Get the OpenID Connect configuration

### Required Parameters
This endpoint does not need any parameter.

### Return type

[**InlineResponse20032**](inline_response_200_32.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **RevokeOAuth2**
> RevokeOAuth2(ctx, token, tokenTypeHint, clientId, clientSecret)
OAuth2 token revocation

Revoke an access or refresh token

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **token** | **string**|  | 
  **tokenTypeHint** | **string**|  | 
  **clientId** | **string**|  | 
  **clientSecret** | **string**|  | 

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/x-www-form-urlencoded
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **TokenOAuth2**
> TokenResponse TokenOAuth2(ctx, grantType, code, redirectUri, clientId, clientSecret, refreshToken, codeVerifier, scope)
OAuth2 token endpoint

Exchange authorization code for tokens

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **grantType** | **string**|  | 
  **code** | **string**|  | 
  **redirectUri** | **string**|  | 
  **clientId** | **string**|  | 
  **clientSecret** | **string**|  | 
  **refreshToken** | **string**|  | 
  **codeVerifier** | **string**|  | 
  **scope** | **string**|  | 

### Return type

[**TokenResponse**](TokenResponse.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/x-www-form-urlencoded
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **UserInfoOAuth2**
> UserInfo UserInfoOAuth2(ctx, )
OpenID Connect userinfo endpoint

Get information about the authenticated user

### Required Parameters
This endpoint does not need any parameter.

### Return type

[**UserInfo**](UserInfo.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

