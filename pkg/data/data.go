package data

import (
	"github.com/go-redis/redis/v8"
	"github.com/juicycleff/frank/ent"
)

type Clients struct {
	DB    *ent.Client
	Redis redis.UniversalClient
}
