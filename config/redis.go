package config

import (
	"fmt"
	"time"
)

// RedisConfig represents Redis connection configuration
type RedisConfig struct {
	// Enabled indicates whether Redis is enabled
	Enabled bool `json:"enabled" yaml:"enabled" env:"REDIS_ENABLED" envDefault:"false"`

	// Host is the Redis server host
	Host string `json:"host" yaml:"host" env:"REDIS_HOST" envDefault:"localhost"`

	// Port is the Redis server port
	Port int `json:"port" yaml:"port" env:"REDIS_PORT" envDefault:"6379"`

	// Username is the Redis username
	Username string `json:"username" yaml:"username" env:"REDIS_USERNAME" envDefault:""`

	// Password is the Redis password
	Password string `json:"password" yaml:"password" env:"REDIS_PASSWORD" envDefault:""`

	// Database is the Redis database number
	Database int `json:"database" yaml:"database" env:"REDIS_DATABASE" envDefault:"0"`

	// MaxRetries is the maximum number of retries before giving up
	MaxRetries int `json:"max_retries" yaml:"max_retries" env:"REDIS_MAX_RETRIES" envDefault:"3"`

	// MinRetryBackoff is the minimum backoff between retries
	MinRetryBackoff time.Duration `json:"min_retry_backoff" yaml:"min_retry_backoff" env:"REDIS_MIN_RETRY_BACKOFF" envDefault:"8ms"`

	// MaxRetryBackoff is the maximum backoff between retries
	MaxRetryBackoff time.Duration `json:"max_retry_backoff" yaml:"max_retry_backoff" env:"REDIS_MAX_RETRY_BACKOFF" envDefault:"512ms"`

	// DialTimeout is the timeout for establishing new connections
	DialTimeout time.Duration `json:"dial_timeout" yaml:"dial_timeout" env:"REDIS_DIAL_TIMEOUT" envDefault:"5s"`

	// ReadTimeout is the timeout for reading a response from the server
	ReadTimeout time.Duration `json:"read_timeout" yaml:"read_timeout" env:"REDIS_READ_TIMEOUT" envDefault:"3s"`

	// WriteTimeout is the timeout for writing a request to the server
	WriteTimeout time.Duration `json:"write_timeout" yaml:"write_timeout" env:"REDIS_WRITE_TIMEOUT" envDefault:"3s"`

	// PoolSize is the maximum number of socket connections
	PoolSize int `json:"pool_size" yaml:"pool_size" env:"REDIS_POOL_SIZE" envDefault:"10"`

	// PoolTimeout is the timeout for getting a connection from the pool
	PoolTimeout time.Duration `json:"pool_timeout" yaml:"pool_timeout" env:"REDIS_POOL_TIMEOUT" envDefault:"4s"`

	// MinIdleConns is the minimum number of idle connections
	MinIdleConns int `json:"min_idle_conns" yaml:"min_idle_conns" env:"REDIS_MIN_IDLE_CONNS" envDefault:"2"`

	// MaxIdleConns is the maximum number of idle connections
	MaxIdleConns int `json:"max_idle_conns" yaml:"max_idle_conns" env:"REDIS_MAX_IDLE_CONNS" envDefault:"10"`

	// ConnMaxIdleTime is the maximum amount of time a connection can be idle
	ConnMaxIdleTime time.Duration `json:"conn_max_idle_time" yaml:"conn_max_idle_time" env:"REDIS_CONN_MAX_IDLE_TIME" envDefault:"5m"`

	// ConnMaxLifetime is the maximum amount of time a connection may be reused
	ConnMaxLifetime time.Duration `json:"conn_max_lifetime" yaml:"conn_max_lifetime" env:"REDIS_CONN_MAX_LIFETIME" envDefault:"1h"`

	// KeyPrefix is the prefix for all Redis keys
	KeyPrefix string `json:"key_prefix" yaml:"key_prefix" env:"REDIS_KEY_PREFIX" envDefault:"frank:"`

	// TLS indicates whether to use TLS for Redis connections
	TLS bool `json:"tls" yaml:"tls" env:"REDIS_TLS" envDefault:"false"`

	// TLSSkipVerify indicates whether to skip TLS verification
	TLSSkipVerify bool `json:"tls_skip_verify" yaml:"tls_skip_verify" env:"REDIS_TLS_SKIP_VERIFY" envDefault:"false"`
}

// GetAddress returns the Redis server address in the format host:port
func (c *RedisConfig) GetAddress() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// GetKeyPrefix returns the Redis key prefix
func (c *RedisConfig) GetKeyPrefix() string {
	return c.KeyPrefix
}

// FormatKey formats a Redis key with the configured prefix
func (c *RedisConfig) FormatKey(key string) string {
	return c.KeyPrefix + key
}
