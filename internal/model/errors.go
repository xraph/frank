package model

import (
	"github.com/danielgtaylor/huma/v2"
)

type ErrorSchemaResponse struct {
	Code    string `json:"code"`
	Content *huma.Response
}

// Error Codes
const (
	// 4xx Client Errors
	BadRequestCode        = "400"
	UnauthorizedCode      = "401"
	PaymentRequiredCode   = "402"
	ForbiddenCode         = "403"
	NotFoundCode          = "404"
	MethodNotAllowedCode  = "405"
	NotAcceptableCode     = "406"
	ProxyAuthRequiredCode = "407"
	RequestTimeoutCode    = "408"
	ConflictCode          = "409"
	GoneCode              = "410"
	LengthRequiredCode    = "411"
	PrecondFailedCode     = "412"
	PayloadTooLargeCode   = "413"
	URITooLongCode        = "414"
	UnsupportedMediaCode  = "415"
	RangeNotSatisfyCode   = "416"
	ExpectationFailedCode = "417"
	TeapotCode            = "418" // April Fools' joke
	MisdirectedReqCode    = "421"
	UnprocessableCode     = "422"
	LockedCode            = "423"
	FailedDependencyCode  = "424"
	TooEarlyCode          = "425"
	UpgradeRequiredCode   = "426"
	PrecondRequiredCode   = "428"
	TooManyRequestsCode   = "429"
	HeadersTooLargeCode   = "431"
	LegalReasonsCode      = "451"

	// 5xx Server Errors
	InternalServerCode      = "500"
	NotImplementedCode      = "501"
	BadGatewayCode          = "502"
	ServiceUnavailableCode  = "503"
	GatewayTimeoutCode      = "504"
	HTTPVersionCode         = "505"
	VariantNegotiatesCode   = "506"
	InsufficientStorageCode = "507"
	LoopDetectedCode        = "508"
	NotExtendedCode         = "510"
	NetworkAuthReqCode      = "511"
)

// Error Types
const (
	// 4xx Client Errors
	BadRequestType        = "BAD_REQUEST"
	UnauthorizedType      = "UNAUTHORIZED"
	PaymentRequiredType   = "PAYMENT_REQUIRED"
	ForbiddenType         = "FORBIDDEN"
	NotFoundType          = "NOT_FOUND"
	MethodNotAllowedType  = "METHOD_NOT_ALLOWED"
	NotAcceptableType     = "NOT_ACCEPTABLE"
	ProxyAuthRequiredType = "PROXY_AUTH_REQUIRED"
	RequestTimeoutType    = "REQUEST_TIMEOUT"
	ConflictType          = "CONFLICT"
	GoneType              = "GONE"
	LengthRequiredType    = "LENGTH_REQUIRED"
	PrecondFailedType     = "PRECONDITION_FAILED"
	PayloadTooLargeType   = "PAYLOAD_TOO_LARGE"
	URITooLongType        = "URI_TOO_LONG"
	UnsupportedMediaType  = "UNSUPPORTED_MEDIA_TYPE"
	RangeNotSatisfyType   = "RANGE_NOT_SATISFIABLE"
	ExpectationFailedType = "EXPECTATION_FAILED"
	TeapotType            = "I_AM_A_TEAPOT"
	MisdirectedReqType    = "MISDIRECTED_REQUEST"
	UnprocessableType     = "UNPROCESSABLE_ENTITY"
	LockedType            = "LOCKED"
	FailedDependencyType  = "FAILED_DEPENDENCY"
	TooEarlyType          = "TOO_EARLY"
	UpgradeRequiredType   = "UPGRADE_REQUIRED"
	PrecondRequiredType   = "PRECONDITION_REQUIRED"
	TooManyRequestsType   = "TOO_MANY_REQUESTS"
	HeadersTooLargeType   = "HEADERS_TOO_LARGE"
	LegalReasonsType      = "UNAVAILABLE_LEGAL_REASONS"

	// 5xx Server Errors
	InternalServerType      = "INTERNAL_SERVER_ERROR"
	NotImplementedType      = "NOT_IMPLEMENTED"
	BadGatewayType          = "BAD_GATEWAY"
	ServiceUnavailableType  = "SERVICE_UNAVAILABLE"
	GatewayTimeoutType      = "GATEWAY_TIMEOUT"
	HTTPVersionType         = "HTTP_VERSION_NOT_SUPPORTED"
	VariantNegotiatesType   = "VARIANT_ALSO_NEGOTIATES"
	InsufficientStorageType = "INSUFFICIENT_STORAGE"
	LoopDetectedType        = "LOOP_DETECTED"
	NotExtendedType         = "NOT_EXTENDED"
	NetworkAuthReqType      = "NETWORK_AUTH_REQUIRED"
)

// Export hidden functions
var (
	BadRequestError              = badRequestError
	UnauthorizedError            = unauthorizedError
	PaymentRequiredError         = paymentRequiredError
	ForbiddenError               = forbiddenError
	NotFoundError                = notFoundError
	MethodNotAllowedError        = methodNotAllowedError
	NotAcceptableError           = notAcceptableError
	ProxyAuthRequiredError       = proxyAuthRequiredError
	RequestTimeoutError          = requestTimeoutError
	ConflictError                = conflictError
	GoneError                    = goneError
	LengthRequiredError          = lengthRequiredError
	PreconditionFailedError      = preconditionFailedError
	PayloadTooLargeError         = payloadTooLargeError
	UriTooLongError              = uriTooLongError
	UnsupportedMediaTypeError    = unsupportedMediaTypeError
	RangeNotSatisfiableError     = rangeNotSatisfiableError
	ExpectationFailedError       = expectationFailedError
	TeapotError                  = teapotError
	MisdirectedRequestError      = misdirectedRequestError
	UnprocessableEntityError     = unprocessableEntityError
	LockedError                  = lockedError
	FailedDependencyError        = failedDependencyError
	TooEarlyError                = tooEarlyError
	UpgradeRequiredError         = upgradeRequiredError
	PreconditionRequiredError    = preconditionRequiredError
	TooManyRequestsError         = tooManyRequestsError
	HeadersTooLargeError         = headersTooLargeError
	LegalReasonsError            = legalReasonsError
	InternalServerError          = internalServerError
	NotImplementedError          = notImplementedError
	BadGatewayError              = badGatewayError
	ServiceUnavailableError      = serviceUnavailableError
	GatewayTimeoutError          = gatewayTimeoutError
	HTTPVersionNotSupportedError = httpVersionNotSupportedError
	VariantAlsoNegotiatesError   = variantAlsoNegotiatesError
	InsufficientStorageError     = insufficientStorageError
	LoopDetectedError            = loopDetectedError
	NotExtendedError             = notExtendedError
	NetworkAuthRequiredError     = networkAuthRequiredError
)

func ErrorSchema(code string) *huma.Schema {
	return &huma.Schema{
		Type: huma.TypeObject,
		Properties: map[string]*huma.Schema{
			"code": {
				Type:        huma.TypeString,
				Description: "Error code",
				Examples:    []any{code},
			},
			"message": {
				Type:        huma.TypeString,
				Description: "Error message",
				Examples:    []any{"Error description"},
			},
			"details": {
				Type:        huma.TypeObject,
				Description: "Additional error details",
			},
			"id": {
				Type:        huma.TypeString,
				Description: "Unique error ID",
				Examples:    []any{"err_123456"},
			},
		},
		Required: []string{"code", "message"},
	}
}

// 4xx Client Errors

func badRequestError(desc string) ErrorSchemaResponse {
	description := "Bad request"
	if desc != "" {
		description = desc
	}
	return ErrorSchemaResponse{
		Code: BadRequestCode,
		Content: &huma.Response{
			Description: description,
			Content: map[string]*huma.MediaType{
				"application/json": {
					Schema: ErrorSchema(BadRequestType),
				},
			},
		},
	}
}

func unauthorizedError() ErrorSchemaResponse {
	return ErrorSchemaResponse{
		Code: UnauthorizedCode,
		Content: &huma.Response{
			Description: "Unauthorized",
			Content: map[string]*huma.MediaType{
				"application/json": {
					Schema: ErrorSchema(UnauthorizedType),
				},
			},
		},
	}
}

func paymentRequiredError() ErrorSchemaResponse {
	return ErrorSchemaResponse{
		Code: PaymentRequiredCode,
		Content: &huma.Response{
			Description: "Payment required",
			Content: map[string]*huma.MediaType{
				"application/json": {
					Schema: ErrorSchema(PaymentRequiredType),
				},
			},
		},
	}
}

func forbiddenError() ErrorSchemaResponse {
	return ErrorSchemaResponse{
		Code: ForbiddenCode,
		Content: &huma.Response{
			Description: "Forbidden",
			Content: map[string]*huma.MediaType{
				"application/json": {
					Schema: ErrorSchema(ForbiddenType),
				},
			},
		},
	}
}

func notFoundError(desc string) ErrorSchemaResponse {
	description := "Not found"
	if desc != "" {
		description = desc
	}
	return ErrorSchemaResponse{
		Code: NotFoundCode, // Fixed the code (was 403 in your example)
		Content: &huma.Response{
			Description: description,
			Content: map[string]*huma.MediaType{
				"application/json": {
					Schema: ErrorSchema(NotFoundType),
				},
			},
		},
	}
}

func methodNotAllowedError() ErrorSchemaResponse {
	return ErrorSchemaResponse{
		Code: MethodNotAllowedCode,
		Content: &huma.Response{
			Description: "Method not allowed",
			Content: map[string]*huma.MediaType{
				"application/json": {
					Schema: ErrorSchema(MethodNotAllowedType),
				},
			},
		},
	}
}

func notAcceptableError() ErrorSchemaResponse {
	return ErrorSchemaResponse{
		Code: NotAcceptableCode,
		Content: &huma.Response{
			Description: "Not acceptable",
			Content: map[string]*huma.MediaType{
				"application/json": {
					Schema: ErrorSchema(NotAcceptableType),
				},
			},
		},
	}
}

func proxyAuthRequiredError() ErrorSchemaResponse {
	return ErrorSchemaResponse{
		Code: ProxyAuthRequiredCode,
		Content: &huma.Response{
			Description: "Proxy authentication required",
			Content: map[string]*huma.MediaType{
				"application/json": {
					Schema: ErrorSchema(ProxyAuthRequiredType),
				},
			},
		},
	}
}

func requestTimeoutError() ErrorSchemaResponse {
	return ErrorSchemaResponse{
		Code: RequestTimeoutCode,
		Content: &huma.Response{
			Description: "Request timeout",
			Content: map[string]*huma.MediaType{
				"application/json": {
					Schema: ErrorSchema(RequestTimeoutType),
				},
			},
		},
	}
}

func conflictError(desc string) ErrorSchemaResponse {
	description := "Conflict"
	if desc != "" {
		description = desc
	}
	return ErrorSchemaResponse{
		Code: ConflictCode,
		Content: &huma.Response{
			Description: description,
			Content: map[string]*huma.MediaType{
				"application/json": {
					Schema: ErrorSchema(ConflictType),
				},
			},
		},
	}
}

func goneError() ErrorSchemaResponse {
	return ErrorSchemaResponse{
		Code: GoneCode,
		Content: &huma.Response{
			Description: "Gone",
			Content: map[string]*huma.MediaType{
				"application/json": {
					Schema: ErrorSchema(GoneType),
				},
			},
		},
	}
}

func lengthRequiredError() ErrorSchemaResponse {
	return ErrorSchemaResponse{
		Code: LengthRequiredCode,
		Content: &huma.Response{
			Description: "Length required",
			Content: map[string]*huma.MediaType{
				"application/json": {
					Schema: ErrorSchema(LengthRequiredType),
				},
			},
		},
	}
}

func preconditionFailedError() ErrorSchemaResponse {
	return ErrorSchemaResponse{
		Code: PrecondFailedCode,
		Content: &huma.Response{
			Description: "Precondition failed",
			Content: map[string]*huma.MediaType{
				"application/json": {
					Schema: ErrorSchema(PrecondFailedType),
				},
			},
		},
	}
}

func payloadTooLargeError() ErrorSchemaResponse {
	return ErrorSchemaResponse{
		Code: PayloadTooLargeCode,
		Content: &huma.Response{
			Description: "Payload too large",
			Content: map[string]*huma.MediaType{
				"application/json": {
					Schema: ErrorSchema(PayloadTooLargeType),
				},
			},
		},
	}
}

func uriTooLongError() ErrorSchemaResponse {
	return ErrorSchemaResponse{
		Code: URITooLongCode,
		Content: &huma.Response{
			Description: "URI too long",
			Content: map[string]*huma.MediaType{
				"application/json": {
					Schema: ErrorSchema(URITooLongType),
				},
			},
		},
	}
}

func unsupportedMediaTypeError() ErrorSchemaResponse {
	return ErrorSchemaResponse{
		Code: UnsupportedMediaCode,
		Content: &huma.Response{
			Description: "Unsupported media type",
			Content: map[string]*huma.MediaType{
				"application/json": {
					Schema: ErrorSchema(UnsupportedMediaType),
				},
			},
		},
	}
}

func rangeNotSatisfiableError() ErrorSchemaResponse {
	return ErrorSchemaResponse{
		Code: RangeNotSatisfyCode,
		Content: &huma.Response{
			Description: "Range not satisfiable",
			Content: map[string]*huma.MediaType{
				"application/json": {
					Schema: ErrorSchema(RangeNotSatisfyType),
				},
			},
		},
	}
}

func expectationFailedError() ErrorSchemaResponse {
	return ErrorSchemaResponse{
		Code: ExpectationFailedCode,
		Content: &huma.Response{
			Description: "Expectation failed",
			Content: map[string]*huma.MediaType{
				"application/json": {
					Schema: ErrorSchema(ExpectationFailedType),
				},
			},
		},
	}
}

func teapotError() ErrorSchemaResponse {
	return ErrorSchemaResponse{
		Code: TeapotCode,
		Content: &huma.Response{
			Description: "I'm a teapot",
			Content: map[string]*huma.MediaType{
				"application/json": {
					Schema: ErrorSchema(TeapotType),
				},
			},
		},
	}
}

func misdirectedRequestError() ErrorSchemaResponse {
	return ErrorSchemaResponse{
		Code: MisdirectedReqCode,
		Content: &huma.Response{
			Description: "Misdirected request",
			Content: map[string]*huma.MediaType{
				"application/json": {
					Schema: ErrorSchema(MisdirectedReqType),
				},
			},
		},
	}
}

func unprocessableEntityError(desc string) ErrorSchemaResponse {
	description := "Unprocessable entity"
	if desc != "" {
		description = desc
	}
	return ErrorSchemaResponse{
		Code: UnprocessableCode,
		Content: &huma.Response{
			Description: description,
			Content: map[string]*huma.MediaType{
				"application/json": {
					Schema: ErrorSchema(UnprocessableType),
				},
			},
		},
	}
}

func lockedError() ErrorSchemaResponse {
	return ErrorSchemaResponse{
		Code: LockedCode,
		Content: &huma.Response{
			Description: "Locked",
			Content: map[string]*huma.MediaType{
				"application/json": {
					Schema: ErrorSchema(LockedType),
				},
			},
		},
	}
}

func failedDependencyError() ErrorSchemaResponse {
	return ErrorSchemaResponse{
		Code: FailedDependencyCode,
		Content: &huma.Response{
			Description: "Failed dependency",
			Content: map[string]*huma.MediaType{
				"application/json": {
					Schema: ErrorSchema(FailedDependencyType),
				},
			},
		},
	}
}

func tooEarlyError() ErrorSchemaResponse {
	return ErrorSchemaResponse{
		Code: TooEarlyCode,
		Content: &huma.Response{
			Description: "Too early",
			Content: map[string]*huma.MediaType{
				"application/json": {
					Schema: ErrorSchema(TooEarlyType),
				},
			},
		},
	}
}

func upgradeRequiredError() ErrorSchemaResponse {
	return ErrorSchemaResponse{
		Code: UpgradeRequiredCode,
		Content: &huma.Response{
			Description: "Upgrade required",
			Content: map[string]*huma.MediaType{
				"application/json": {
					Schema: ErrorSchema(UpgradeRequiredType),
				},
			},
		},
	}
}

func preconditionRequiredError() ErrorSchemaResponse {
	return ErrorSchemaResponse{
		Code: PrecondRequiredCode,
		Content: &huma.Response{
			Description: "Precondition required",
			Content: map[string]*huma.MediaType{
				"application/json": {
					Schema: ErrorSchema(PrecondRequiredType),
				},
			},
		},
	}
}

func tooManyRequestsError() ErrorSchemaResponse {
	return ErrorSchemaResponse{
		Code: TooManyRequestsCode,
		Content: &huma.Response{
			Description: "Too many requests",
			Content: map[string]*huma.MediaType{
				"application/json": {
					Schema: ErrorSchema(TooManyRequestsType),
				},
			},
		},
	}
}

func headersTooLargeError() ErrorSchemaResponse {
	return ErrorSchemaResponse{
		Code: HeadersTooLargeCode,
		Content: &huma.Response{
			Description: "Headers too large",
			Content: map[string]*huma.MediaType{
				"application/json": {
					Schema: ErrorSchema(HeadersTooLargeType),
				},
			},
		},
	}
}

func legalReasonsError() ErrorSchemaResponse {
	return ErrorSchemaResponse{
		Code: LegalReasonsCode,
		Content: &huma.Response{
			Description: "Unavailable for legal reasons",
			Content: map[string]*huma.MediaType{
				"application/json": {
					Schema: ErrorSchema(LegalReasonsType),
				},
			},
		},
	}
}

// 5xx Server Errors

func internalServerError(desc string) ErrorSchemaResponse {
	description := "Internal server error"
	if desc != "" {
		description = desc
	}
	return ErrorSchemaResponse{
		Code: InternalServerCode,
		Content: &huma.Response{
			Description: description,
			Content: map[string]*huma.MediaType{
				"application/json": {
					Schema: ErrorSchema(InternalServerType),
				},
			},
		},
	}
}

func notImplementedError() ErrorSchemaResponse {
	return ErrorSchemaResponse{
		Code: NotImplementedCode,
		Content: &huma.Response{
			Description: "Not implemented",
			Content: map[string]*huma.MediaType{
				"application/json": {
					Schema: ErrorSchema(NotImplementedType),
				},
			},
		},
	}
}

func badGatewayError() ErrorSchemaResponse {
	return ErrorSchemaResponse{
		Code: BadGatewayCode,
		Content: &huma.Response{
			Description: "Bad gateway",
			Content: map[string]*huma.MediaType{
				"application/json": {
					Schema: ErrorSchema(BadGatewayType),
				},
			},
		},
	}
}

func serviceUnavailableError() ErrorSchemaResponse {
	return ErrorSchemaResponse{
		Code: ServiceUnavailableCode,
		Content: &huma.Response{
			Description: "Service unavailable",
			Content: map[string]*huma.MediaType{
				"application/json": {
					Schema: ErrorSchema(ServiceUnavailableType),
				},
			},
		},
	}
}

func gatewayTimeoutError() ErrorSchemaResponse {
	return ErrorSchemaResponse{
		Code: GatewayTimeoutCode,
		Content: &huma.Response{
			Description: "Gateway timeout",
			Content: map[string]*huma.MediaType{
				"application/json": {
					Schema: ErrorSchema(GatewayTimeoutType),
				},
			},
		},
	}
}

func httpVersionNotSupportedError() ErrorSchemaResponse {
	return ErrorSchemaResponse{
		Code: HTTPVersionCode,
		Content: &huma.Response{
			Description: "HTTP version not supported",
			Content: map[string]*huma.MediaType{
				"application/json": {
					Schema: ErrorSchema(HTTPVersionType),
				},
			},
		},
	}
}

func variantAlsoNegotiatesError() ErrorSchemaResponse {
	return ErrorSchemaResponse{
		Code: VariantNegotiatesCode,
		Content: &huma.Response{
			Description: "Variant also negotiates",
			Content: map[string]*huma.MediaType{
				"application/json": {
					Schema: ErrorSchema(VariantNegotiatesType),
				},
			},
		},
	}
}

func insufficientStorageError() ErrorSchemaResponse {
	return ErrorSchemaResponse{
		Code: InsufficientStorageCode,
		Content: &huma.Response{
			Description: "Insufficient storage",
			Content: map[string]*huma.MediaType{
				"application/json": {
					Schema: ErrorSchema(InsufficientStorageType),
				},
			},
		},
	}
}

func loopDetectedError() ErrorSchemaResponse {
	return ErrorSchemaResponse{
		Code: LoopDetectedCode,
		Content: &huma.Response{
			Description: "Loop detected",
			Content: map[string]*huma.MediaType{
				"application/json": {
					Schema: ErrorSchema(LoopDetectedType),
				},
			},
		},
	}
}

func notExtendedError() ErrorSchemaResponse {
	return ErrorSchemaResponse{
		Code: NotExtendedCode,
		Content: &huma.Response{
			Description: "Not extended",
			Content: map[string]*huma.MediaType{
				"application/json": {
					Schema: ErrorSchema(NotExtendedType),
				},
			},
		},
	}
}

func networkAuthRequiredError() ErrorSchemaResponse {
	return ErrorSchemaResponse{
		Code: NetworkAuthReqCode,
		Content: &huma.Response{
			Description: "Network authentication required",
			Content: map[string]*huma.MediaType{
				"application/json": {
					Schema: ErrorSchema(NetworkAuthReqType),
				},
			},
		},
	}
}

// Common default errors that most APIs need
var defaultErrors = []ErrorSchemaResponse{
	badRequestError(""),          // 400 - Invalid request parameters
	notFoundError(""),            // 404 - Resource not found
	conflictError(""),            // 409 - Resource conflict
	unprocessableEntityError(""), // 422 - Validation failed
	internalServerError(""),      // 500 - Server error
}

// MergeErrorResponses takes a base response map and a list of error schemas
// and merges them into a single map[string]*huma.Response. If no error schemas
// are provided, it adds standard errors (400, 401, 403, 404, 409, 422, 500).
func MergeErrorResponses(baseResponses map[string]*huma.Response, requireAuth bool, errorSchemas ...ErrorSchemaResponse) map[string]*huma.Response {
	// If baseResponses is nil, initialize it
	if baseResponses == nil {
		baseResponses = make(map[string]*huma.Response)
	}

	if requireAuth {
		baseResponses[unauthorizedError().Code] = unauthorizedError().Content
	}

	// Merge each error schema into the response map
	for _, errorSchema := range append(defaultErrors, errorSchemas...) {
		baseResponses[errorSchema.Code] = errorSchema.Content
	}

	return baseResponses
}
