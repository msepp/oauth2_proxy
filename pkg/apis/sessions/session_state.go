package sessions

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/msepp/oauth2_proxy/v4/pkg/encryption"
)

// SessionState is used to store information about the currently authenticated user session
type SessionState struct {
	AccessToken  string    `json:",omitempty"`
	IDToken      string    `json:",omitempty"`
	CreatedAt    time.Time `json:"-"`
	ExpiresOn    time.Time `json:"-"`
	RefreshToken string    `json:",omitempty"`
	Email        string    `json:",omitempty"`
	User         string    `json:",omitempty"`
}

// SessionStateJSON is used to encode SessionState into JSON without exposing time.Time zero value
type SessionStateJSON struct {
	*SessionState
	CreatedAt *time.Time `json:",omitempty"`
	ExpiresOn *time.Time `json:",omitempty"`
}

// IsExpired checks whether the session has expired
func (s *SessionState) IsExpired() bool {
	if !s.ExpiresOn.IsZero() && s.ExpiresOn.Before(time.Now()) {
		return true
	}
	return false
}

// Age returns the age of a session
func (s *SessionState) Age() time.Duration {
	if !s.CreatedAt.IsZero() {
		return time.Now().Truncate(time.Second).Sub(s.CreatedAt)
	}
	return 0
}

// String constructs a summary of the session state
func (s *SessionState) String() string {
	o := fmt.Sprintf("Session{email:%s user:%s", s.Email, s.User)
	if s.AccessToken != "" {
		o += " token:true"
	}
	if s.IDToken != "" {
		o += " id_token:true"
	}
	if !s.CreatedAt.IsZero() {
		o += fmt.Sprintf(" created:%s", s.CreatedAt)
	}
	if !s.ExpiresOn.IsZero() {
		o += fmt.Sprintf(" expires:%s", s.ExpiresOn)
	}
	if s.RefreshToken != "" {
		o += " refresh_token:true"
	}
	return o + "}"
}

// EncodeSessionState returns string representation of the current session
func (s *SessionState) EncodeSessionState(c *encryption.Cipher) (string, error) {
	var ss SessionState
	if c == nil {
		// Store only Email and User when cipher is unavailable
		ss.Email = s.Email
		ss.User = s.User
	} else {
		ss = *s
		var err error
		if ss.Email != "" {
			ss.Email, err = c.Encrypt(ss.Email)
			if err != nil {
				return "", err
			}
		}
		if ss.User != "" {
			ss.User, err = c.Encrypt(ss.User)
			if err != nil {
				return "", err
			}
		}
		if ss.AccessToken != "" {
			ss.AccessToken, err = c.Encrypt(ss.AccessToken)
			if err != nil {
				return "", err
			}
		}
		if ss.IDToken != "" {
			ss.IDToken, err = c.Encrypt(ss.IDToken)
			if err != nil {
				return "", err
			}
		}
		if ss.RefreshToken != "" {
			ss.RefreshToken, err = c.Encrypt(ss.RefreshToken)
			if err != nil {
				return "", err
			}
		}
	}
	// Embed SessionState and ExpiresOn pointer into SessionStateJSON
	ssj := &SessionStateJSON{SessionState: &ss}
	if !ss.CreatedAt.IsZero() {
		ssj.CreatedAt = &ss.CreatedAt
	}
	if !ss.ExpiresOn.IsZero() {
		ssj.ExpiresOn = &ss.ExpiresOn
	}
	b, err := json.Marshal(ssj)
	return string(b), err
}

// legacyDecodeSessionStatePlain decodes older plain session state string
func legacyDecodeSessionStatePlain(v string) (*SessionState, error) {
	chunks := strings.Split(v, " ")
	if len(chunks) != 2 {
		return nil, fmt.Errorf("invalid session state (legacy: expected 2 chunks for user/email got %d)", len(chunks))
	}

	user := strings.TrimPrefix(chunks[1], "user:")
	email := strings.TrimPrefix(chunks[0], "email:")

	return &SessionState{User: user, Email: email}, nil
}

// legacyDecodeSessionState attempts to decode the session state string
// generated by v3.1.0 or older
func legacyDecodeSessionState(v string, c *encryption.Cipher) (*SessionState, error) {
	chunks := strings.Split(v, "|")

	if c == nil {
		if len(chunks) != 1 {
			return nil, fmt.Errorf("invalid session state (legacy: expected 1 chunk for plain got %d)", len(chunks))
		}
		return legacyDecodeSessionStatePlain(chunks[0])
	}

	if len(chunks) != 4 && len(chunks) != 5 {
		return nil, fmt.Errorf("invalid session state (legacy: expected 4 or 5 chunks for full got %d)", len(chunks))
	}

	i := 0
	ss, err := legacyDecodeSessionStatePlain(chunks[i])
	if err != nil {
		return nil, err
	}

	i++
	ss.AccessToken = chunks[i]

	if len(chunks) == 5 {
		// SessionState with IDToken in v3.1.0
		i++
		ss.IDToken = chunks[i]
	}

	i++
	ts, err := strconv.Atoi(chunks[i])
	if err != nil {
		return nil, fmt.Errorf("invalid session state (legacy: wrong expiration time: %s)", err)
	}
	ss.ExpiresOn = time.Unix(int64(ts), 0)

	i++
	ss.RefreshToken = chunks[i]

	return ss, nil
}

// DecodeSessionState decodes the session cookie string into a SessionState
func DecodeSessionState(v string, c *encryption.Cipher) (*SessionState, error) {
	var ssj SessionStateJSON
	var ss *SessionState
	err := json.Unmarshal([]byte(v), &ssj)
	if err == nil && ssj.SessionState != nil {
		// Extract SessionState and CreatedAt,ExpiresOn value from SessionStateJSON
		ss = ssj.SessionState
		if ssj.CreatedAt != nil {
			ss.CreatedAt = *ssj.CreatedAt
		}
		if ssj.ExpiresOn != nil {
			ss.ExpiresOn = *ssj.ExpiresOn
		}
	} else {
		// Try to decode a legacy string when json.Unmarshal failed
		ss, err = legacyDecodeSessionState(v, c)
		if err != nil {
			return nil, err
		}
	}
	if c == nil {
		// Load only Email and User when cipher is unavailable
		ss = &SessionState{
			Email: ss.Email,
			User:  ss.User,
		}
	} else {
		// Backward compatibility with using unencrypted Email
		if ss.Email != "" {
			decryptedEmail, errEmail := c.Decrypt(ss.Email)
			if errEmail == nil {
				ss.Email = decryptedEmail
			}
		}
		// Backward compatibility with using unencrypted User
		if ss.User != "" {
			decryptedUser, errUser := c.Decrypt(ss.User)
			if errUser == nil {
				ss.User = decryptedUser
			}
		}
		if ss.AccessToken != "" {
			ss.AccessToken, err = c.Decrypt(ss.AccessToken)
			if err != nil {
				return nil, err
			}
		}
		if ss.IDToken != "" {
			ss.IDToken, err = c.Decrypt(ss.IDToken)
			if err != nil {
				return nil, err
			}
		}
		if ss.RefreshToken != "" {
			ss.RefreshToken, err = c.Decrypt(ss.RefreshToken)
			if err != nil {
				return nil, err
			}
		}
	}
	if ss.User == "" {
		ss.User = ss.Email
	}
	return ss, nil
}
