package sessions

import (
	"fmt"

	"github.com/msepp/oauth2_proxy/v4/pkg/apis/options"
	"github.com/msepp/oauth2_proxy/v4/pkg/apis/sessions"
	"github.com/msepp/oauth2_proxy/v4/pkg/sessions/cookie"
	"github.com/msepp/oauth2_proxy/v4/pkg/sessions/redis"
)

// NewSessionStore creates a SessionStore from the provided configuration
func NewSessionStore(opts *options.SessionOptions, cookieOpts *options.CookieOptions) (sessions.SessionStore, error) {
	switch opts.Type {
	case options.CookieSessionStoreType:
		return cookie.NewCookieSessionStore(opts, cookieOpts)
	case options.RedisSessionStoreType:
		return redis.NewRedisSessionStore(opts, cookieOpts)
	default:
		return nil, fmt.Errorf("unknown session store type '%s'", opts.Type)
	}
}
