package common

type APIKeyRateLimits struct {
	RequestsPerMinute int `json:"requestsPerMinute" example:"100" doc:"Requests per minute limit"`
	RequestsPerHour   int `json:"requestsPerHour" example:"5000" doc:"Requests per hour limit"`
	RequestsPerDay    int `json:"requestsPerDay" example:"100000" doc:"Requests per day limit"`
	BurstLimit        int `json:"burstLimit" example:"50" doc:"Burst request limit"`
}
