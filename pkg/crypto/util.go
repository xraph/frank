package crypto

import (
	"strings"
	"time"

	"github.com/juicycleff/frank/config"
	"github.com/juicycleff/frank/pkg/errors"
)

type Util interface {
	JWT() JWTManager
	Random() RandomGenerator
	Hasher() Hasher
	PasswordHasher() PasswordHasher
}

type cryptoUtil struct {
	passwordHasher PasswordHasher
	jwtManager     JWTManager
	random         RandomGenerator
	hasher         Hasher
}

func (c *cryptoUtil) JWT() JWTManager {
	return c.jwtManager
}

func (c *cryptoUtil) Random() RandomGenerator {
	return c.random
}
func (c *cryptoUtil) Hasher() Hasher {
	return c.hasher
}
func (c *cryptoUtil) PasswordHasher() PasswordHasher {
	return c.passwordHasher
}

func New(cfg *config.Config) (Util, error) {
	if cfg == nil {
		return nil, errors.New(errors.CodeInternalServer, "config is required")
	}

	man, err := NewJWTManager(&JWTConfig{
		SecretKey:           cfg.Auth.TokenSecretKey,
		SigningMethod:       SigningMethod(cfg.Auth.TokenSigningMethod),
		Issuer:              cfg.Auth.TokenIssuer,
		Audience:            cfg.Auth.TokenAudience,
		AccessTokenExpiry:   cfg.Auth.AccessTokenDuration,
		RefreshTokenExpiry:  cfg.Auth.RefreshTokenDuration,
		VerifyTokenExpiry:   cfg.Auth.VerificationTokenDuration,
		MagicLinkExpiry:     cfg.Auth.MagicLinkDuration,
		InvitationExpiry:    24 * time.Hour,   // Default 24 hours for invitations
		PasswordResetExpiry: 15 * time.Minute, // Default 15 minutes for password reset

		PublicKey:  "",
		PrivateKey: "",
	})
	if err != nil {
		return nil, err
	}

	hashConfig := DefaultHashConfig()
	if cfg.Auth.PasswordPolicy.BcryptCost > 0 {
		hashConfig.Cost = cfg.Auth.PasswordPolicy.BcryptCost
	}
	if len(cfg.Auth.PasswordPolicy.Algorithm) > 0 {
		hashConfig.Algorithm = HashAlgorithm(strings.ToLower(cfg.Auth.PasswordPolicy.Algorithm))
	}

	return &cryptoUtil{
		jwtManager:     man,
		random:         NewRandomGenerator(),
		hasher:         NewHasher(hashConfig.Algorithm),
		passwordHasher: NewPasswordHasher(hashConfig),
	}, nil
}
