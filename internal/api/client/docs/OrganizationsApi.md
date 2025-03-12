# {{classname}}

All URIs are relative to *https://auth.example.com/api/v1*

Method | HTTP request | Description
------------- | ------------- | -------------
[**AddOrganizationMember**](OrganizationsApi.md#AddOrganizationMember) | **Post** /organizations/{id}/members | Add organization member
[**CreateOrganization**](OrganizationsApi.md#CreateOrganization) | **Post** /organizations | Create organization
[**DeleteOrganization**](OrganizationsApi.md#DeleteOrganization) | **Delete** /organizations/{id} | Delete organization
[**DisableOrganizationFeature**](OrganizationsApi.md#DisableOrganizationFeature) | **Delete** /organizations/{id}/features/{featureKey} | Disable organization feature
[**EnableOrganizationFeature**](OrganizationsApi.md#EnableOrganizationFeature) | **Post** /organizations/{id}/features | Enable organization feature
[**GetOrganization**](OrganizationsApi.md#GetOrganization) | **Get** /organizations/{id} | Get organization
[**ListOrganizationFeatures**](OrganizationsApi.md#ListOrganizationFeatures) | **Get** /organizations/{id}/features | List organization features
[**ListOrganizationMembers**](OrganizationsApi.md#ListOrganizationMembers) | **Get** /organizations/{id}/members | List organization members
[**ListOrganizations**](OrganizationsApi.md#ListOrganizations) | **Get** /organizations | List organizations
[**RemoveOrganizationMember**](OrganizationsApi.md#RemoveOrganizationMember) | **Delete** /organizations/{id}/members/{userId} | Remove organization member
[**UpdateOrganization**](OrganizationsApi.md#UpdateOrganization) | **Put** /organizations/{id} | Update organization
[**UpdateOrganizationMember**](OrganizationsApi.md#UpdateOrganizationMember) | **Put** /organizations/{id}/members/{userId} | Update organization member

# **AddOrganizationMember**
> InlineResponse20024 AddOrganizationMember(ctx, body, id)
Add organization member

Add a user to an organization

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **body** | [**IdMembersBody**](IdMembersBody.md)|  | 
  **id** | **string**|  | 

### Return type

[**InlineResponse20024**](inline_response_200_24.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **CreateOrganization**
> Organization CreateOrganization(ctx, body)
Create organization

Create a new organization

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **body** | [**OrganizationsBody**](OrganizationsBody.md)|  | 

### Return type

[**Organization**](Organization.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **DeleteOrganization**
> DeleteOrganization(ctx, id)
Delete organization

Delete a specific organization

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

# **DisableOrganizationFeature**
> DisableOrganizationFeature(ctx, id, featureKey)
Disable organization feature

Disable a feature for an organization

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **id** | **string**|  | 
  **featureKey** | **string**|  | 

### Return type

 (empty response body)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **EnableOrganizationFeature**
> InlineResponse20027 EnableOrganizationFeature(ctx, body, id)
Enable organization feature

Enable a feature for an organization

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **body** | [**IdFeaturesBody**](IdFeaturesBody.md)|  | 
  **id** | **string**|  | 

### Return type

[**InlineResponse20027**](inline_response_200_27.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **GetOrganization**
> Organization GetOrganization(ctx, id)
Get organization

Get a specific organization

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **id** | **string**|  | 

### Return type

[**Organization**](Organization.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ListOrganizationFeatures**
> InlineResponse20026 ListOrganizationFeatures(ctx, id)
List organization features

List enabled features for an organization

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **id** | **string**|  | 

### Return type

[**InlineResponse20026**](inline_response_200_26.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ListOrganizationMembers**
> InlineResponse20022 ListOrganizationMembers(ctx, id, optional)
List organization members

List members of an organization

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **id** | **string**|  | 
 **optional** | ***OrganizationsApiListOrganizationMembersOpts** | optional parameters | nil if no parameters

### Optional Parameters
Optional parameters are passed through a pointer to a OrganizationsApiListOrganizationMembersOpts struct
Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **offset** | **optional.Int32**|  | [default to 0]
 **limit** | **optional.Int32**|  | [default to 20]
 **search** | **optional.String**|  | 

### Return type

[**InlineResponse20022**](inline_response_200_22.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ListOrganizations**
> InlineResponse20023 ListOrganizations(ctx, optional)
List organizations

List organizations with pagination and filtering

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
 **optional** | ***OrganizationsApiListOrganizationsOpts** | optional parameters | nil if no parameters

### Optional Parameters
Optional parameters are passed through a pointer to a OrganizationsApiListOrganizationsOpts struct
Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **offset** | **optional.Int32**|  | [default to 0]
 **limit** | **optional.Int32**|  | [default to 20]
 **search** | **optional.String**|  | 

### Return type

[**InlineResponse20023**](inline_response_200_23.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **RemoveOrganizationMember**
> RemoveOrganizationMember(ctx, id, userId)
Remove organization member

Remove a user from an organization

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **id** | **string**|  | 
  **userId** | **string**|  | 

### Return type

 (empty response body)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **UpdateOrganization**
> Organization UpdateOrganization(ctx, body, id)
Update organization

Update a specific organization

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **body** | [**OrganizationsIdBody**](OrganizationsIdBody.md)|  | 
  **id** | **string**|  | 

### Return type

[**Organization**](Organization.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **UpdateOrganizationMember**
> InlineResponse20025 UpdateOrganizationMember(ctx, body, id, userId)
Update organization member

Update a member's roles in an organization

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **body** | [**MembersUserIdBody**](MembersUserIdBody.md)|  | 
  **id** | **string**|  | 
  **userId** | **string**|  | 

### Return type

[**InlineResponse20025**](inline_response_200_25.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

