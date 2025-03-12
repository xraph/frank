# {{classname}}

All URIs are relative to *https://auth.example.com/api/v1*

Method | HTTP request | Description
------------- | ------------- | -------------
[**CreateWebhook**](WebhooksApi.md#CreateWebhook) | **Post** /webhooks | Create webhook
[**DeleteWebhook**](WebhooksApi.md#DeleteWebhook) | **Delete** /webhooks/{id} | Delete webhook
[**GetWebhook**](WebhooksApi.md#GetWebhook) | **Get** /webhooks/{id} | Get webhook
[**ListWebhookEvents**](WebhooksApi.md#ListWebhookEvents) | **Get** /webhooks/{id}/events | List webhook events
[**ListWebhooks**](WebhooksApi.md#ListWebhooks) | **Get** /webhooks | List webhooks
[**ReplayWebhookEvent**](WebhooksApi.md#ReplayWebhookEvent) | **Post** /webhooks/{id}/events/{eventId}/replay | Replay webhook event
[**TriggerWebhookEvent**](WebhooksApi.md#TriggerWebhookEvent) | **Post** /webhooks/trigger | Trigger webhook event
[**UpdateWebhook**](WebhooksApi.md#UpdateWebhook) | **Put** /webhooks/{id} | Update webhook

# **CreateWebhook**
> Webhook CreateWebhook(ctx, body)
Create webhook

Create a new webhook

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **body** | [**WebhooksBody**](WebhooksBody.md)|  | 

### Return type

[**Webhook**](Webhook.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **DeleteWebhook**
> DeleteWebhook(ctx, id)
Delete webhook

Delete a specific webhook

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

# **GetWebhook**
> Webhook GetWebhook(ctx, id)
Get webhook

Get a specific webhook

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **id** | **string**|  | 

### Return type

[**Webhook**](Webhook.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ListWebhookEvents**
> InlineResponse20030 ListWebhookEvents(ctx, id, optional)
List webhook events

List events for a specific webhook

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **id** | **string**|  | 
 **optional** | ***WebhooksApiListWebhookEventsOpts** | optional parameters | nil if no parameters

### Optional Parameters
Optional parameters are passed through a pointer to a WebhooksApiListWebhookEventsOpts struct
Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **offset** | **optional.Int32**|  | [default to 0]
 **limit** | **optional.Int32**|  | [default to 20]
 **eventType** | **optional.String**|  | 
 **delivered** | **optional.Bool**|  | 

### Return type

[**InlineResponse20030**](inline_response_200_30.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ListWebhooks**
> InlineResponse20029 ListWebhooks(ctx, optional)
List webhooks

List webhooks with pagination

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
 **optional** | ***WebhooksApiListWebhooksOpts** | optional parameters | nil if no parameters

### Optional Parameters
Optional parameters are passed through a pointer to a WebhooksApiListWebhooksOpts struct
Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **offset** | **optional.Int32**|  | [default to 0]
 **limit** | **optional.Int32**|  | [default to 20]
 **eventTypes** | [**optional.Interface of []string**](string.md)|  | 

### Return type

[**InlineResponse20029**](inline_response_200_29.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ReplayWebhookEvent**
> WebhookEvent ReplayWebhookEvent(ctx, id, eventId)
Replay webhook event

Replay a specific webhook event

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **id** | **string**|  | 
  **eventId** | **string**|  | 

### Return type

[**WebhookEvent**](WebhookEvent.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **TriggerWebhookEvent**
> WebhookEvent TriggerWebhookEvent(ctx, body)
Trigger webhook event

Manually trigger a webhook event

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **body** | [**WebhooksTriggerBody**](WebhooksTriggerBody.md)|  | 

### Return type

[**WebhookEvent**](WebhookEvent.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **UpdateWebhook**
> Webhook UpdateWebhook(ctx, body, id)
Update webhook

Update a specific webhook

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **body** | [**WebhooksIdBody**](WebhooksIdBody.md)|  | 
  **id** | **string**|  | 

### Return type

[**Webhook**](Webhook.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

