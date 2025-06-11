package notification

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/juicycleff/frank/pkg/errors"
	"github.com/juicycleff/frank/pkg/logging"
	"go.uber.org/zap"
)

// PhoneValidator defines the interface for phone number validation
type PhoneValidator interface {
	Validate(ctx context.Context, phoneNumber string) (*PhoneValidation, error)
	ValidateBatch(ctx context.Context, phoneNumbers []string) ([]*PhoneValidation, error)
	GetCarrierInfo(ctx context.Context, phoneNumber string) (*CarrierInfo, error)
	GetRiskScore(ctx context.Context, phoneNumber string) (*RiskAssessment, error)
	IsReachable(ctx context.Context, phoneNumber string) (*ReachabilityCheck, error)
	GetCostEstimate(ctx context.Context, phoneNumber string) (*CostInfo, error)
	ValidateFormat(phoneNumber string) (*FormatValidation, error)
	ParseNumber(phoneNumber string) (*ParsedNumber, error)
}

// PhoneValidatorConfig represents phone validator configuration
type PhoneValidatorConfig struct {
	Providers           []ValidationProvider `json:"providers"`
	CacheEnabled        bool                 `json:"cacheEnabled"`
	CacheTTL            time.Duration        `json:"cacheTtl"`
	EnableCarrierLookup bool                 `json:"enableCarrierLookup"`
	EnableRiskScoring   bool                 `json:"enableRiskScoring"`
	RiskThresholds      RiskThresholds       `json:"riskThresholds"`
	CountryRestrictions []string             `json:"countryRestrictions,omitempty"`
	BlockedPatterns     []string             `json:"blockedPatterns,omitempty"`
	Timeout             time.Duration        `json:"timeout"`
}

// ValidationProvider represents a phone validation provider
type ValidationProvider struct {
	Name     string                 `json:"name"`
	Type     string                 `json:"type"` // twilio, numverify, etc.
	APIKey   string                 `json:"apiKey"`
	Config   map[string]interface{} `json:"config"`
	Priority int                    `json:"priority"`
	Enabled  bool                   `json:"enabled"`
}

// RiskThresholds represents risk scoring thresholds
type RiskThresholds struct {
	LowRisk        float64 `json:"lowRisk"`
	MediumRisk     float64 `json:"mediumRisk"`
	HighRisk       float64 `json:"highRisk"`
	BlockThreshold float64 `json:"blockThreshold"`
}

// FormatValidation represents basic format validation result
type FormatValidation struct {
	IsValid      bool     `json:"isValid"`
	Format       string   `json:"format"` // E164, national, international
	ErrorCode    string   `json:"errorCode,omitempty"`
	ErrorMessage string   `json:"errorMessage,omitempty"`
	Suggestions  []string `json:"suggestions,omitempty"`
}

// ParsedNumber represents a parsed phone number
type ParsedNumber struct {
	Original            string `json:"original"`
	E164Format          string `json:"e164Format"`
	NationalFormat      string `json:"nationalFormat"`
	InternationalFormat string `json:"internationalFormat"`
	CountryCode         string `json:"countryCode"`
	NationalNumber      string `json:"nationalNumber"`
	Extension           string `json:"extension,omitempty"`
	IsPossible          bool   `json:"isPossible"`
	IsValid             bool   `json:"isValid"`
}

// RiskAssessment represents phone number risk assessment
type RiskAssessment struct {
	PhoneNumber  string                 `json:"phoneNumber"`
	RiskScore    float64                `json:"riskScore"` // 0-1, higher is riskier
	RiskLevel    string                 `json:"riskLevel"` // low, medium, high, critical
	RiskFactors  []RiskFactor           `json:"riskFactors"`
	Recommended  string                 `json:"recommended"` // allow, flag, block
	Confidence   float64                `json:"confidence"`
	LastAssessed time.Time              `json:"lastAssessed"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// RiskFactor represents a risk factor
type RiskFactor struct {
	Type        string  `json:"type"`
	Description string  `json:"description"`
	Impact      float64 `json:"impact"` // Contribution to risk score
	Severity    string  `json:"severity"`
}

// ReachabilityCheck represents phone reachability check
type ReachabilityCheck struct {
	PhoneNumber  string    `json:"phoneNumber"`
	IsReachable  bool      `json:"isReachable"`
	Status       string    `json:"status"`
	ResponseTime int       `json:"responseTime"` // milliseconds
	LastChecked  time.Time `json:"lastChecked"`
	Error        string    `json:"error,omitempty"`
}

// CostInfo represents SMS cost information
type CostInfo struct {
	PhoneNumber string    `json:"phoneNumber"`
	CountryCode string    `json:"countryCode"`
	CostPerSMS  float64   `json:"costPerSms"`
	Currency    string    `json:"currency"`
	Provider    string    `json:"provider"`
	Route       string    `json:"route"`
	LastUpdated time.Time `json:"lastUpdated"`
}

// phoneValidator implements the PhoneValidator interface
type phoneValidator struct {
	config    PhoneValidatorConfig
	providers map[string]PhoneValidationProvider
	cache     ValidationCache
	logger    logging.Logger
	metrics   *ValidationMetrics
}

// PhoneValidationProvider interface for different validation providers
type PhoneValidationProvider interface {
	ValidateNumber(ctx context.Context, phoneNumber string) (*ProviderValidationResult, error)
	GetCarrierInfo(ctx context.Context, phoneNumber string) (*ProviderCarrierInfo, error)
	CheckReachability(ctx context.Context, phoneNumber string) (*ProviderReachabilityResult, error)
	GetCostInfo(ctx context.Context, phoneNumber string) (*ProviderCostInfo, error)
}

// ProviderValidationResult represents validation result from a provider
type ProviderValidationResult struct {
	IsValid     bool                   `json:"isValid"`
	PhoneNumber string                 `json:"phoneNumber"`
	CountryCode string                 `json:"countryCode"`
	CountryName string                 `json:"countryName"`
	Carrier     string                 `json:"carrier"`
	LineType    string                 `json:"lineType"`
	IsRoaming   bool                   `json:"isRoaming"`
	Confidence  float64                `json:"confidence"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// ProviderCarrierInfo represents carrier info from a provider
type ProviderCarrierInfo struct {
	CarrierName string `json:"carrierName"`
	NetworkType string `json:"networkType"`
	MCC         string `json:"mcc"`
	MNC         string `json:"mnc"`
	IsPortedIn  bool   `json:"isPortedIn"`
	IsPortedOut bool   `json:"isPortedOut"`
}

// ProviderReachabilityResult represents reachability result from a provider
type ProviderReachabilityResult struct {
	IsReachable  bool   `json:"isReachable"`
	Status       string `json:"status"`
	ResponseTime int    `json:"responseTime"`
	Error        string `json:"error,omitempty"`
}

// ProviderCostInfo represents cost info from a provider
type ProviderCostInfo struct {
	CostPerSMS float64 `json:"costPerSms"`
	Currency   string  `json:"currency"`
	Route      string  `json:"route"`
}

// ValidationCache interface for caching validation results
type ValidationCache interface {
	Get(ctx context.Context, key string) (*PhoneValidation, error)
	Set(ctx context.Context, key string, validation *PhoneValidation, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
}

// ValidationMetrics represents validation metrics
type ValidationMetrics struct {
	TotalValidations int64                     `json:"totalValidations"`
	ValidNumbers     int64                     `json:"validNumbers"`
	InvalidNumbers   int64                     `json:"invalidNumbers"`
	CacheHits        int64                     `json:"cacheHits"`
	CacheMisses      int64                     `json:"cacheMisses"`
	ProviderStats    map[string]*ProviderStats `json:"providerStats"`
	CountryStats     map[string]*CountryStats  `json:"countryStats"`
	mutex            sync.RWMutex
}

// ProviderStats represents provider-specific statistics
type ProviderStats struct {
	Requests       int64         `json:"requests"`
	Successes      int64         `json:"successes"`
	Failures       int64         `json:"failures"`
	AverageLatency time.Duration `json:"averageLatency"`
	LastUsed       time.Time     `json:"lastUsed"`
}

// CountryStats represents country-specific statistics
type CountryStats struct {
	TotalNumbers   int64   `json:"totalNumbers"`
	ValidNumbers   int64   `json:"validNumbers"`
	InvalidNumbers int64   `json:"invalidNumbers"`
	AverageRisk    float64 `json:"averageRisk"`

	Sent         int     `json:"sent" doc:"Messages sent"`
	Delivered    int     `json:"delivered" doc:"Messages delivered"`
	Failed       int     `json:"failed" doc:"Messages failed"`
	DeliveryRate float64 `json:"deliveryRate" doc:"Delivery rate"`
	AverageCost  float64 `json:"averageCost" doc:"Average cost"`
}

// Country and carrier data structures
var countryCodeMap = map[string]CountryInfo{
	"1":  {Code: "1", Name: "United States", ISO: "US", Timezone: "America/New_York"},
	"44": {Code: "44", Name: "United Kingdom", ISO: "GB", Timezone: "Europe/London"},
	"33": {Code: "33", Name: "France", ISO: "FR", Timezone: "Europe/Paris"},
	"49": {Code: "49", Name: "Germany", ISO: "DE", Timezone: "Europe/Berlin"},
	"81": {Code: "81", Name: "Japan", ISO: "JP", Timezone: "Asia/Tokyo"},
	"86": {Code: "86", Name: "China", ISO: "CN", Timezone: "Asia/Shanghai"},
	"91": {Code: "91", Name: "India", ISO: "IN", Timezone: "Asia/Kolkata"},
	"55": {Code: "55", Name: "Brazil", ISO: "BR", Timezone: "America/Sao_Paulo"},
	"61": {Code: "61", Name: "Australia", ISO: "AU", Timezone: "Australia/Sydney"},
	"7":  {Code: "7", Name: "Russia", ISO: "RU", Timezone: "Europe/Moscow"},
	// Add more countries as needed
}

// CountryInfo represents country information
type CountryInfo struct {
	Code     string `json:"code"`
	Name     string `json:"name"`
	ISO      string `json:"iso"`
	Timezone string `json:"timezone"`
}

// NewPhoneValidator creates a new phone validator instance
func NewPhoneValidator(config PhoneValidatorConfig, logger logging.Logger) (PhoneValidator, error) {
	pv := &phoneValidator{
		config:    config,
		providers: make(map[string]PhoneValidationProvider),
		logger:    logger,
		metrics: &ValidationMetrics{
			ProviderStats: make(map[string]*ProviderStats),
			CountryStats:  make(map[string]*CountryStats),
		},
	}

	// Initialize providers
	for _, providerConfig := range config.Providers {
		if !providerConfig.Enabled {
			continue
		}

		provider, err := createValidationProvider(providerConfig)
		if err != nil {
			logger.Warn("failed to create validation provider", zap.String("provider", providerConfig.Name), zap.Error(err))
			continue
		}

		pv.providers[providerConfig.Name] = provider
	}

	// Initialize cache if enabled
	if config.CacheEnabled {
		pv.cache = NewInMemoryValidationCache()
	}

	return pv, nil
}

// Validate validates a phone number
func (pv *phoneValidator) Validate(ctx context.Context, phoneNumber string) (*PhoneValidation, error) {
	start := time.Now()
	defer func() {
		pv.updateMetrics("total_validations", 1)
		pv.logger.Debug("phone validation completed", zap.String("phoneNumber", phoneNumber), zap.Duration("duration", time.Since(start)))
	}()

	// Check cache first
	if pv.cache != nil {
		cached, err := pv.cache.Get(ctx, phoneNumber)
		if err == nil && cached != nil {
			pv.updateMetrics("cache_hits", 1)
			return cached, nil
		}
		pv.updateMetrics("cache_misses", 1)
	}

	// Basic format validation
	formatResult, err := pv.ValidateFormat(phoneNumber)
	if err != nil || !formatResult.IsValid {
		result := &PhoneValidation{
			PhoneNumber:    phoneNumber,
			IsValid:        false,
			ValidationTime: time.Now(),
		}
		if err != nil {
			result.Reputation = "invalid_format"
		}
		return result, nil
	}

	// Parse the number
	parsed, err := pv.ParseNumber(phoneNumber)
	if err != nil {
		return &PhoneValidation{
			PhoneNumber:    phoneNumber,
			IsValid:        false,
			ValidationTime: time.Now(),
		}, nil
	}

	// Validate with providers
	validation := &PhoneValidation{
		PhoneNumber:    phoneNumber,
		FormattedE164:  parsed.E164Format,
		CountryCode:    parsed.CountryCode,
		IsValid:        parsed.IsValid,
		ValidationTime: time.Now(),
	}

	// Get country information
	if countryInfo, exists := countryCodeMap[parsed.CountryCode]; exists {
		validation.CountryName = countryInfo.Name
		validation.Timezone = countryInfo.Timezone
	}

	// Enhanced validation with providers
	if len(pv.providers) > 0 {
		providerResult, err := pv.validateWithProviders(ctx, phoneNumber)
		if err != nil {
			pv.logger.Warn("provider validation failed", zap.String("phoneNumber", phoneNumber), zap.Error(err))
		} else {
			validation.IsValid = providerResult.IsValid
			validation.Carrier = providerResult.Carrier
			validation.LineType = providerResult.LineType
			validation.IsRoaming = providerResult.IsRoaming
			validation.IsReachable = true // Assume reachable if provider validates
		}
	}

	// Risk assessment
	if pv.config.EnableRiskScoring {
		riskAssessment, err := pv.GetRiskScore(ctx, phoneNumber)
		if err != nil {
			pv.logger.Warn("risk assessment failed", zap.String("phoneNumber", phoneNumber), zap.Error(err))
		} else {
			validation.RiskScore = riskAssessment.RiskScore
			validation.Reputation = riskAssessment.RiskLevel
		}
	}

	// Check restrictions
	if pv.isRestricted(validation) {
		validation.IsValid = false
		validation.Reputation = "restricted"
	}

	// Cache result
	if pv.cache != nil {
		_ = pv.cache.Set(ctx, phoneNumber, validation, pv.config.CacheTTL)
	}

	// Update metrics
	if validation.IsValid {
		pv.updateMetrics("valid_numbers", 1)
	} else {
		pv.updateMetrics("invalid_numbers", 1)
	}

	return validation, nil
}

// ValidateBatch validates multiple phone numbers
func (pv *phoneValidator) ValidateBatch(ctx context.Context, phoneNumbers []string) ([]*PhoneValidation, error) {
	results := make([]*PhoneValidation, len(phoneNumbers))

	for i, phoneNumber := range phoneNumbers {
		validation, err := pv.Validate(ctx, phoneNumber)
		if err != nil {
			results[i] = &PhoneValidation{
				PhoneNumber:    phoneNumber,
				IsValid:        false,
				ValidationTime: time.Now(),
			}
		} else {
			results[i] = validation
		}
	}

	return results, nil
}

// ValidateFormat performs basic format validation
func (pv *phoneValidator) ValidateFormat(phoneNumber string) (*FormatValidation, error) {
	result := &FormatValidation{
		IsValid: false,
		Format:  "unknown",
	}

	// Clean the phone number
	cleaned := strings.ReplaceAll(phoneNumber, " ", "")
	cleaned = strings.ReplaceAll(cleaned, "-", "")
	cleaned = strings.ReplaceAll(cleaned, "(", "")
	cleaned = strings.ReplaceAll(cleaned, ")", "")

	// E.164 format validation
	e164Regex := regexp.MustCompile(`^\+[1-9]\d{1,14}$`)
	if e164Regex.MatchString(cleaned) {
		result.IsValid = true
		result.Format = "E164"
		return result, nil
	}

	// National format (starting with 0 or without country code)
	if len(cleaned) >= 7 && len(cleaned) <= 15 {
		nationalRegex := regexp.MustCompile(`^[0-9]+$`)
		if nationalRegex.MatchString(cleaned) {
			result.IsValid = true
			result.Format = "national"
			result.Suggestions = []string{
				"Consider using E.164 format (+country code + number)",
				"Example: +1234567890",
			}
			return result, nil
		}
	}

	result.ErrorCode = "INVALID_FORMAT"
	result.ErrorMessage = "Phone number must be in E.164 format (+country code + number)"
	result.Suggestions = []string{
		"Use E.164 format: +[country code][number]",
		"Example: +1234567890 for US numbers",
		"Remove spaces, dashes, and parentheses",
	}

	return result, nil
}

// ParseNumber parses a phone number into its components
func (pv *phoneValidator) ParseNumber(phoneNumber string) (*ParsedNumber, error) {
	result := &ParsedNumber{
		Original: phoneNumber,
	}

	// Clean the number
	cleaned := strings.ReplaceAll(phoneNumber, " ", "")
	cleaned = strings.ReplaceAll(cleaned, "-", "")
	cleaned = strings.ReplaceAll(cleaned, "(", "")
	cleaned = strings.ReplaceAll(cleaned, ")", "")

	// Parse E.164 format
	if strings.HasPrefix(cleaned, "+") {
		result.E164Format = cleaned

		// Extract country code (simplified logic)
		for code := range countryCodeMap {
			if strings.HasPrefix(cleaned[1:], code) {
				result.CountryCode = code
				result.NationalNumber = cleaned[1+len(code):]
				result.InternationalFormat = fmt.Sprintf("+%s %s", code, result.NationalNumber)
				result.NationalFormat = fmt.Sprintf("0%s", result.NationalNumber)
				result.IsPossible = true
				result.IsValid = len(result.NationalNumber) >= 7 && len(result.NationalNumber) <= 10
				break
			}
		}
	} else {
		// Assume national format, might need country context
		result.NationalNumber = cleaned
		result.NationalFormat = cleaned
		result.IsPossible = len(cleaned) >= 7 && len(cleaned) <= 15
	}

	return result, nil
}

// GetCarrierInfo gets carrier information for a phone number
func (pv *phoneValidator) GetCarrierInfo(ctx context.Context, phoneNumber string) (*CarrierInfo, error) {
	if len(pv.providers) == 0 {
		return nil, errors.New(errors.CodeNotImplemented, "no carrier lookup providers configured")
	}

	// Try providers in priority order
	for _, provider := range pv.providers {
		carrierInfo, err := provider.GetCarrierInfo(ctx, phoneNumber)
		if err != nil {
			continue
		}

		parsed, _ := pv.ParseNumber(phoneNumber)

		result := &CarrierInfo{
			PhoneNumber: phoneNumber,
			CarrierName: carrierInfo.CarrierName,
			NetworkType: carrierInfo.NetworkType,
			MCC:         carrierInfo.MCC,
			MNC:         carrierInfo.MNC,
			IsPortedIn:  carrierInfo.IsPortedIn,
			IsPortedOut: carrierInfo.IsPortedOut,
			LastUpdated: time.Now(),
		}

		if parsed != nil {
			result.CountryCode = parsed.CountryCode
			if countryInfo, exists := countryCodeMap[parsed.CountryCode]; exists {
				result.CountryName = countryInfo.Name
			}
		}

		return result, nil
	}

	return nil, errors.New(errors.CodeNotFound, "carrier information not found")
}

// GetRiskScore calculates risk score for a phone number
func (pv *phoneValidator) GetRiskScore(ctx context.Context, phoneNumber string) (*RiskAssessment, error) {
	assessment := &RiskAssessment{
		PhoneNumber:  phoneNumber,
		RiskScore:    0.0,
		RiskLevel:    "low",
		RiskFactors:  []RiskFactor{},
		Recommended:  "allow",
		Confidence:   0.8,
		LastAssessed: time.Now(),
	}

	var totalRisk float64
	var factors []RiskFactor

	// Basic format risk
	formatValidation, err := pv.ValidateFormat(phoneNumber)
	if err != nil || !formatValidation.IsValid {
		factors = append(factors, RiskFactor{
			Type:        "format",
			Description: "Invalid phone number format",
			Impact:      0.5,
			Severity:    "high",
		})
		totalRisk += 0.5
	}

	// Parse for additional checks
	parsed, err := pv.ParseNumber(phoneNumber)
	if err == nil {
		// Country-based risk (simplified)
		if countryRisk := pv.getCountryRisk(parsed.CountryCode); countryRisk > 0 {
			factors = append(factors, RiskFactor{
				Type:        "country",
				Description: fmt.Sprintf("Higher risk country code: %s", parsed.CountryCode),
				Impact:      countryRisk,
				Severity:    "medium",
			})
			totalRisk += countryRisk
		}

		// Pattern-based risk
		if pv.matchesBlockedPattern(phoneNumber) {
			factors = append(factors, RiskFactor{
				Type:        "pattern",
				Description: "Phone number matches blocked pattern",
				Impact:      0.8,
				Severity:    "high",
			})
			totalRisk += 0.8
		}
	}

	// Carrier-based risk (if available)
	if pv.config.EnableCarrierLookup {
		carrierInfo, err := pv.GetCarrierInfo(ctx, phoneNumber)
		if err == nil {
			if carrierInfo.LineType == "voip" {
				factors = append(factors, RiskFactor{
					Type:        "line_type",
					Description: "VoIP number detected",
					Impact:      0.3,
					Severity:    "medium",
				})
				totalRisk += 0.3
			}
		}
	}

	// Normalize risk score (0-1)
	assessment.RiskScore = min(totalRisk, 1.0)
	assessment.RiskFactors = factors

	// Determine risk level and recommendation
	if assessment.RiskScore < pv.config.RiskThresholds.LowRisk {
		assessment.RiskLevel = "low"
		assessment.Recommended = "allow"
	} else if assessment.RiskScore < pv.config.RiskThresholds.MediumRisk {
		assessment.RiskLevel = "medium"
		assessment.Recommended = "flag"
	} else if assessment.RiskScore < pv.config.RiskThresholds.HighRisk {
		assessment.RiskLevel = "high"
		assessment.Recommended = "flag"
	} else {
		assessment.RiskLevel = "critical"
		assessment.Recommended = "block"
	}

	if assessment.RiskScore >= pv.config.RiskThresholds.BlockThreshold {
		assessment.Recommended = "block"
	}

	return assessment, nil
}

// IsReachable checks if a phone number is reachable
func (pv *phoneValidator) IsReachable(ctx context.Context, phoneNumber string) (*ReachabilityCheck, error) {
	start := time.Now()

	result := &ReachabilityCheck{
		PhoneNumber: phoneNumber,
		LastChecked: time.Now(),
	}

	// Try providers for reachability check
	for _, provider := range pv.providers {
		reachabilityResult, err := provider.CheckReachability(ctx, phoneNumber)
		if err != nil {
			result.Error = err.Error()
			continue
		}

		result.IsReachable = reachabilityResult.IsReachable
		result.Status = reachabilityResult.Status
		result.ResponseTime = int(time.Since(start).Milliseconds())
		return result, nil
	}

	// Fallback: assume reachable if format is valid
	formatValidation, err := pv.ValidateFormat(phoneNumber)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	result.IsReachable = formatValidation.IsValid
	result.Status = "unknown"
	result.ResponseTime = int(time.Since(start).Milliseconds())

	return result, nil
}

// GetCostEstimate gets cost estimate for sending SMS to a phone number
func (pv *phoneValidator) GetCostEstimate(ctx context.Context, phoneNumber string) (*CostInfo, error) {
	parsed, err := pv.ParseNumber(phoneNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to parse phone number: %w", err)
	}

	// Try providers for cost information
	for _, provider := range pv.providers {
		costInfo, err := provider.GetCostInfo(ctx, phoneNumber)
		if err != nil {
			continue
		}

		result := &CostInfo{
			PhoneNumber: phoneNumber,
			CountryCode: parsed.CountryCode,
			CostPerSMS:  costInfo.CostPerSMS,
			Currency:    costInfo.Currency,
			Route:       costInfo.Route,
			LastUpdated: time.Now(),
		}

		return result, nil
	}

	// Fallback: use static cost estimates based on country
	cost := pv.getStaticCostEstimate(parsed.CountryCode)

	return &CostInfo{
		PhoneNumber: phoneNumber,
		CountryCode: parsed.CountryCode,
		CostPerSMS:  cost,
		Currency:    "USD",
		Provider:    "estimate",
		Route:       "default",
		LastUpdated: time.Now(),
	}, nil
}

// Helper methods

func (pv *phoneValidator) validateWithProviders(ctx context.Context, phoneNumber string) (*ProviderValidationResult, error) {
	// Try providers in priority order
	for _, provider := range pv.providers {
		result, err := provider.ValidateNumber(ctx, phoneNumber)
		if err != nil {
			pv.logger.Debug("provider validation failed", zap.String("phoneNumber", phoneNumber), zap.Error(err))
			continue
		}
		return result, nil
	}

	return nil, errors.New(errors.CodeNotFound, "no providers available")
}

func (pv *phoneValidator) isRestricted(validation *PhoneValidation) bool {
	// Check country restrictions
	if len(pv.config.CountryRestrictions) > 0 {
		allowed := false
		for _, allowedCountry := range pv.config.CountryRestrictions {
			if validation.CountryCode == allowedCountry {
				allowed = true
				break
			}
		}
		if !allowed {
			return true
		}
	}

	// Check blocked patterns
	if pv.matchesBlockedPattern(validation.PhoneNumber) {
		return true
	}

	return false
}

func (pv *phoneValidator) matchesBlockedPattern(phoneNumber string) bool {
	for _, pattern := range pv.config.BlockedPatterns {
		if strings.Contains(phoneNumber, pattern) {
			return true
		}
	}
	return false
}

func (pv *phoneValidator) getCountryRisk(countryCode string) float64 {
	// Simplified country risk scoring
	highRiskCountries := map[string]float64{
		"234": 0.4, // Nigeria
		"91":  0.2, // India (higher volume, moderate risk)
		"86":  0.1, // China
	}

	if risk, exists := highRiskCountries[countryCode]; exists {
		return risk
	}

	return 0.0
}

func (pv *phoneValidator) getStaticCostEstimate(countryCode string) float64 {
	// Simplified static cost estimates (per SMS in USD)
	costs := map[string]float64{
		"1":  0.0075, // US/Canada
		"44": 0.045,  // UK
		"33": 0.065,  // France
		"49": 0.085,  // Germany
		"81": 0.12,   // Japan
		"86": 0.035,  // China
		"91": 0.02,   // India
		"55": 0.045,  // Brazil
		"61": 0.075,  // Australia
		"7":  0.065,  // Russia
	}

	if cost, exists := costs[countryCode]; exists {
		return cost
	}

	return 0.10 // Default cost
}

func (pv *phoneValidator) updateMetrics(metric string, value int64) {
	if pv.metrics == nil {
		return
	}

	pv.metrics.mutex.Lock()
	defer pv.metrics.mutex.Unlock()

	switch metric {
	case "total_validations":
		pv.metrics.TotalValidations += value
	case "valid_numbers":
		pv.metrics.ValidNumbers += value
	case "invalid_numbers":
		pv.metrics.InvalidNumbers += value
	case "cache_hits":
		pv.metrics.CacheHits += value
	case "cache_misses":
		pv.metrics.CacheMisses += value
	}
}

// Helper functions
func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// Factory function for creating validation providers
func createValidationProvider(config ValidationProvider) (PhoneValidationProvider, error) {
	switch config.Type {
	case "twilio":
		return NewTwilioValidationProvider(config)
	case "numverify":
		return NewNumverifyValidationProvider(config)
	default:
		return nil, fmt.Errorf("unsupported validation provider: %s", config.Type)
	}
}

// Placeholder provider implementations
func NewTwilioValidationProvider(config ValidationProvider) (PhoneValidationProvider, error) {
	return nil, fmt.Errorf("Twilio validation provider not implemented")
}

func NewNumverifyValidationProvider(config ValidationProvider) (PhoneValidationProvider, error) {
	return nil, fmt.Errorf("Numverify validation provider not implemented")
}

// In-memory cache implementation

type inMemoryValidationCache struct {
	data  map[string]cacheEntry
	mutex sync.RWMutex
}

type cacheEntry struct {
	validation *PhoneValidation
	expiration time.Time
}

func NewInMemoryValidationCache() ValidationCache {
	return &inMemoryValidationCache{
		data: make(map[string]cacheEntry),
	}
}

func (c *inMemoryValidationCache) Get(ctx context.Context, key string) (*PhoneValidation, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	entry, exists := c.data[key]
	if !exists || time.Now().After(entry.expiration) {
		return nil, errors.New(errors.CodeNotFound, "not found in cache")
	}

	return entry.validation, nil
}

func (c *inMemoryValidationCache) Set(ctx context.Context, key string, validation *PhoneValidation, ttl time.Duration) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.data[key] = cacheEntry{
		validation: validation,
		expiration: time.Now().Add(ttl),
	}

	return nil
}

func (c *inMemoryValidationCache) Delete(ctx context.Context, key string) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	delete(c.data, key)
	return nil
}
