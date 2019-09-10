package providers

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"bytes"
	"encoding/json"
	"io/ioutil"
	"time"

	simplejson "github.com/bitly/go-simplejson"
	"github.com/msepp/oauth2_proxy/pkg/apis/sessions"
	"github.com/msepp/oauth2_proxy/pkg/logger"
	"github.com/msepp/oauth2_proxy/pkg/requests"
)

// AzureProvider represents an Azure based Identity Provider
type AzureProvider struct {
	*ProviderData
	Tenant string
}

// NewAzureProvider initiates a new AzureProvider
func NewAzureProvider(p *ProviderData) *AzureProvider {
	p.ProviderName = "Azure"

	if p.ProfileURL == nil || p.ProfileURL.String() == "" {
		p.ProfileURL = &url.URL{
			Scheme:   "https",
			Host:     "graph.windows.net",
			Path:     "/me",
			RawQuery: "api-version=1.6",
		}
	}
	if p.ProtectedResource == nil || p.ProtectedResource.String() == "" {
		p.ProtectedResource = &url.URL{
			Scheme: "https",
			Host:   "graph.windows.net",
		}
	}
	if p.Scope == "" {
		p.Scope = "openid"
	}

	return &AzureProvider{ProviderData: p}
}

// Configure defaults the AzureProvider configuration options
func (p *AzureProvider) Configure(tenant string) {
	p.Tenant = tenant
	if tenant == "" {
		p.Tenant = "common"
	}

	if p.LoginURL == nil || p.LoginURL.String() == "" {
		p.LoginURL = &url.URL{
			Scheme: "https",
			Host:   "login.microsoftonline.com",
			Path:   "/" + p.Tenant + "/oauth2/authorize"}
	}
	if p.RedeemURL == nil || p.RedeemURL.String() == "" {
		p.RedeemURL = &url.URL{
			Scheme: "https",
			Host:   "login.microsoftonline.com",
			Path:   "/" + p.Tenant + "/oauth2/token",
		}
	}
}

func getAzureHeader(accessToken string) http.Header {
	header := make(http.Header)
	header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	return header
}

func getEmailFromJSON(json *simplejson.Json) (string, error) {
	var email string
	var err error

	email, err = json.Get("mail").String()

	if err != nil || email == "" {
		otherMails, otherMailsErr := json.Get("otherMails").Array()
		if len(otherMails) > 0 {
			email = otherMails[0].(string)
		}
		err = otherMailsErr
	}

	return email, err
}

// GetEmailAddress returns the Account email address
func (p *AzureProvider) GetEmailAddress(s *sessions.SessionState) (string, error) {
	var email string
	var err error

	if s.AccessToken == "" {
		return "", errors.New("missing access token")
	}
	req, err := http.NewRequest("GET", p.ProfileURL.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header = getAzureHeader(s.AccessToken)

	json, err := requests.Request(req)

	if err != nil {
		return "", err
	}

	email, err = getEmailFromJSON(json)

	if err == nil && email != "" {
		return email, err
	}

	email, err = json.Get("userPrincipalName").String()

	if err != nil {
		logger.Printf("failed making request %s", err)
		return "", err
	}

	if email == "" {
		logger.Printf("failed to get email address")
		return "", err
	}

	return email, err
}

// Redeem provides a default implementation of the OAuth2 token redemption process
func (p *AzureProvider) Redeem(redirectURL, code string) (s *sessions.SessionState, err error) {
	if code == "" {
		err = errors.New("missing code")
		return
	}

	params := url.Values{}
	params.Add("redirect_uri", redirectURL)
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", p.ClientSecret)
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")
	if p.ProtectedResource != nil && p.ProtectedResource.String() != "" {
		params.Add("resource", p.ProtectedResource.String())
	}

	var req *http.Request
	req, err = http.NewRequest("POST", p.RedeemURL.String(), bytes.NewBufferString(params.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var resp *http.Response
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	var body []byte
	body, err = ioutil.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return
	}

	if resp.StatusCode != 200 {
		err = fmt.Errorf("got %d from %q %s", resp.StatusCode, p.RedeemURL.String(), body)
		return
	}

	// blindly try json and x-www-form-urlencoded
	var jsonResponse struct {
		ExpiresIn    int64  `json:"expires_in,string"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}

	if err = json.Unmarshal(body, &jsonResponse); err != nil {
		err = fmt.Errorf("decoding redeem response failed, %s", err)
		return
	}

	s = &sessions.SessionState{
		CreatedAt:    time.Now(),
		ExpiresOn:    time.Now().Add(time.Duration(jsonResponse.ExpiresIn-300) * time.Second).Truncate(time.Second),
		RefreshToken: jsonResponse.RefreshToken,
		AccessToken:  jsonResponse.AccessToken,
	}
	return
}

// RefreshSessionIfNeeded checks if the session has expired and uses the
// RefreshToken to fetch a new ID token if required
func (p *AzureProvider) RefreshSessionIfNeeded(s *sessions.SessionState) (bool, error) {
	if s == nil || s.ExpiresOn.After(time.Now()) || s.RefreshToken == "" {
		return false, nil
	}

	newSession, err := p.redeemRefreshToken(s.RefreshToken)
	if err != nil {
		logger.Printf("AZURE: redeem failed: %v", err)
		return false, err
	}

	origExpiration := s.ExpiresOn
	s.AccessToken = newSession.AccessToken
	s.RefreshToken = newSession.RefreshToken
	s.Email = newSession.Email
	s.CreatedAt = newSession.CreatedAt
	s.ExpiresOn = newSession.ExpiresOn

	logger.Printf("AZURE: refreshed access token (expired on %s, next: %s)", origExpiration, s.ExpiresOn)
	return true, nil
}

func (p *AzureProvider) redeemRefreshToken(refreshToken string) (*sessions.SessionState, error) {
	// https://docs.microsoft.com/en-us/azure/active-directory/develop/v1-protocols-oauth-code
	params := url.Values{}
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", p.ClientSecret)
	params.Add("refresh_token", refreshToken)
	params.Add("grant_type", "refresh_token")
	params.Add("resource", p.ProtectedResource.String())

	var (
		req *http.Request
		err error
	)
	req, err = http.NewRequest("POST", p.RedeemURL.String(), bytes.NewBufferString(params.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	var body []byte
	body, err = ioutil.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		err = fmt.Errorf("got %d from %q %s", resp.StatusCode, p.RedeemURL.String(), body)
		return nil, err
	}

	var data struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in,string"`
	}
	err = json.Unmarshal(body, &data)
	if err != nil {
		return nil, err
	}

	var s = &sessions.SessionState{
		AccessToken:  data.AccessToken,
		RefreshToken: data.RefreshToken,
		ExpiresOn:    time.Now().Add(time.Duration(data.ExpiresIn-300) * time.Second).Truncate(time.Second),
		CreatedAt:    time.Now(),
	}

	if s.Email, err = p.GetEmailAddress(s); err != nil {
		return nil, err
	}

	return s, nil
}
