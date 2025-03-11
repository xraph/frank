package passkeys

import (
	"github.com/go-redis/redis/v8"
	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/ent"
	"github.com/juicycleff/frank/pkg/logging"
)

// RepositoryType defines the available repository types
type RepositoryType string

const (
	// RepositoryTypeEnt represents the Ent repository
	RepositoryTypeEnt RepositoryType = "ent"
	// RepositoryTypeInMemory represents the in-memory repository
	RepositoryTypeInMemory RepositoryType = "inmemory"
)

// SessionStoreType defines the available session store types
type SessionStoreType string

const (
	// SessionStoreTypeInMemory represents the in-memory session store
	SessionStoreTypeInMemory SessionStoreType = "inmemory"
	// SessionStoreTypeRedis represents the Redis session store
	SessionStoreTypeRedis SessionStoreType = "redis"
)

// CreateRepository creates the appropriate repository based on the provided type
func CreateRepository(
	repoType RepositoryType,
	client *ent.Client,
	logger logging.Logger,
) Repository {
	switch repoType {
	case RepositoryTypeInMemory:
		return NewInMemoryRepository(logger)
	case RepositoryTypeEnt:
		fallthrough
	default:
		return NewEntRepository(client, logger)
	}
}

// CreateSessionStore creates the appropriate session store based on the provided type
func CreateSessionStore(
	storeType SessionStoreType,
	cfg *config.Config,
	redisClient redis.UniversalClient,
	logger logging.Logger,
) SessionStore {
	switch storeType {
	case SessionStoreTypeRedis:
		if redisClient != nil {
			return NewRedisSessionStore(redisClient, "passkey_session", logger)
		}
		// Fall back to in-memory if Redis client is not provided
		logger.Warn("Redis client not provided, falling back to in-memory session store")
		return NewInMemorySessionStore(logger)
	case SessionStoreTypeInMemory:
		fallthrough
	default:
		return NewInMemorySessionStore(logger)
	}
}

// InitPasskeyService initializes the passkey service with appropriate repository and session store
func InitPasskeyService(
	cfg *config.Config,
	client *ent.Client,
	logger logging.Logger,
	redisClient *redis.Client,
) (Service, error) {
	var storeType SessionStoreType

	// Determine session store type from config
	if cfg.Redis.Enabled && cfg.Passkeys.UseRedisSessionStore {
		storeType = SessionStoreTypeRedis
	} else {
		storeType = SessionStoreTypeInMemory
	}

	sessionStore := CreateSessionStore(storeType, cfg, redisClient, logger)

	// Initialize and return the passkey service
	return NewService(cfg, client, logger, sessionStore)
}
