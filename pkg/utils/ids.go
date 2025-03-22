package utils

import (
	"math/rand"
	"time"

	"github.com/oklog/ulid"
)

func NewID() ulid.ULID {
	entropy := rand.New(rand.NewSource(time.Now().UnixNano()))
	id := ulid.MustNew(ulid.Timestamp(time.Now()), entropy)
	return id
}

func NewIDString() string {
	id := NewID()
	return id.String()
}
