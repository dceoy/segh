package github

import (
	"context"
	"crypto/rsa"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/dceoy/segh/internal/config"
	"github.com/dceoy/segh/internal/logging"
	"github.com/golang-jwt/jwt/v5"
)

type Auth struct {
	cfg          config.Config
	key          *rsa.PrivateKey
	existing     string
	bootstrap    *Client
	log          *logging.Logger
	mu           sync.Mutex
	cachedToken  string
	expiresAt    time.Time
	installation int64
}

type staticToken string

func (t staticToken) Token(context.Context) (string, error) {
	return string(t), nil
}

func NewAuth(cfg config.Config, log *logging.Logger) (*Auth, error) {
	auth := &Auth{cfg: cfg, log: log, installation: cfg.Auth.InstallationID}
	if cfg.Auth.AllowExistingToken {
		if token := os.Getenv(cfg.Auth.TokenEnv); token != "" {
			auth.existing = token
			return auth, nil
		}
	}
	if cfg.Auth.AppID <= 0 {
		return nil, fmt.Errorf("auth.app_id is required unless auth.allow_existing_token is enabled and %s is set", cfg.Auth.TokenEnv)
	}
	var pem []byte
	var err error
	switch {
	case cfg.Auth.PrivateKeyFile != "":
		info, statErr := os.Stat(cfg.Auth.PrivateKeyFile)
		if statErr != nil {
			return nil, fmt.Errorf("stat GitHub App private key: %w", statErr)
		}
		if info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("GitHub App private key file must not be accessible by group or others")
		}
		if info.Size() > 1<<20 {
			return nil, fmt.Errorf("GitHub App private key file exceeds 1 MiB")
		}
		pem, err = os.ReadFile(cfg.Auth.PrivateKeyFile) // #nosec G304 -- explicit config path with enforced private permissions.
		if err != nil {
			return nil, fmt.Errorf("read GitHub App private key: %w", err)
		}
	case cfg.Auth.PrivateKeyEnv != "":
		pem = []byte(os.Getenv(cfg.Auth.PrivateKeyEnv))
	}
	if len(pem) == 0 {
		return nil, fmt.Errorf("GitHub App private key is not configured")
	}
	auth.key, err = jwt.ParseRSAPrivateKeyFromPEM(pem)
	if err != nil {
		return nil, fmt.Errorf("parse GitHub App private key: %w", err)
	}
	return auth, nil
}

func (a *Auth) Token(ctx context.Context) (string, error) {
	if a.existing != "" {
		return a.existing, nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cachedToken != "" && time.Until(a.expiresAt) > 5*time.Minute {
		return a.cachedToken, nil
	}
	appJWT, err := a.appJWT()
	if err != nil {
		return "", err
	}
	if a.bootstrap == nil {
		a.bootstrap, err = NewClient(a.cfg, staticToken(appJWT), a.log)
		if err != nil {
			return "", err
		}
	} else {
		a.bootstrap.tokens = staticToken(appJWT)
	}
	if a.installation == 0 {
		var installation struct {
			ID int64 `json:"id"`
		}
		if err := a.bootstrap.Get(ctx, "/orgs/"+pathEscape(a.cfg.Organization)+"/installation", &installation); err != nil {
			return "", fmt.Errorf("discover GitHub App installation: %w", err)
		}
		a.installation = installation.ID
	}
	var response struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	path := "/app/installations/" + strconv.FormatInt(a.installation, 10) + "/access_tokens"
	if err := a.bootstrap.Post(ctx, path, map[string]any{}, &response); err != nil {
		return "", fmt.Errorf("create GitHub App installation token: %w", err)
	}
	if response.Token == "" {
		return "", fmt.Errorf("GitHub returned an empty installation token")
	}
	a.cachedToken = response.Token
	a.expiresAt = response.ExpiresAt
	return a.cachedToken, nil
}

func (a *Auth) appJWT() (string, error) {
	now := time.Now()
	claims := jwt.RegisteredClaims{
		Issuer:    strconv.FormatInt(a.cfg.Auth.AppID, 10),
		IssuedAt:  jwt.NewNumericDate(now.Add(-30 * time.Second)),
		ExpiresAt: jwt.NewNumericDate(now.Add(9 * time.Minute)),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := token.SignedString(a.key)
	if err != nil {
		return "", fmt.Errorf("sign GitHub App JWT: %w", err)
	}
	return signed, nil
}
