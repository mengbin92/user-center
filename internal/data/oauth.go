package data

import (
	"context"
	"fmt"
	"github.com/mengbin92/user-center/pkg/jsonx"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"

	"github.com/mengbin92/user-center/internal/biz"
)

// NewOAuthRegistry builds the enabled provider adapters from environment
// variables. Providers without a client id/secret are omitted.
func NewOAuthRegistry(log *zap.Logger) map[string]biz.OAuthProvider {
	out := map[string]biz.OAuthProvider{}
	if id, secret := os.Getenv("OAUTH_GITHUB_CLIENT_ID"), os.Getenv("OAUTH_GITHUB_CLIENT_SECRET"); id != "" && secret != "" {
		out["github"] = &githubProvider{
			conf: &oauth2.Config{ClientID: id, ClientSecret: secret, Endpoint: github.Endpoint, Scopes: []string{"read:user", "user:email"}},
			log:  log, userInfoURL: "https://api.github.com/user", emailsURL: "https://api.github.com/user/emails",
		}
	}
	if id, secret := os.Getenv("OAUTH_GOOGLE_CLIENT_ID"), os.Getenv("OAUTH_GOOGLE_CLIENT_SECRET"); id != "" && secret != "" {
		out["google"] = &googleProvider{
			conf: &oauth2.Config{ClientID: id, ClientSecret: secret, Endpoint: google.Endpoint, Scopes: []string{"openid", "email", "profile"}},
			log:  log, userInfoURL: "https://openidconnect.googleapis.com/v1/userinfo",
		}
	}
	return out
}

type githubProvider struct {
	conf        *oauth2.Config
	log         *zap.Logger
	userInfoURL string
	emailsURL   string
}

func (p *githubProvider) Name() string { return "github" }
func (p *githubProvider) AuthCodeURL(state, redirectURI string) string {
	c := *p.conf
	c.RedirectURL = redirectURI
	return c.AuthCodeURL(state, oauth2.AccessTypeOnline)
}

func (p *githubProvider) Exchange(ctx context.Context, code, redirectURI string) (biz.OAuthProfile, error) {
	c := *p.conf
	c.RedirectURL = redirectURI
	token, err := c.Exchange(ctx, code)
	if err != nil {
		return biz.OAuthProfile{}, err
	}
	client := c.Client(ctx, token)
	var raw struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if err := getJSON(ctx, client, p.userInfoURL, &raw); err != nil {
		return biz.OAuthProfile{}, err
	}
	email := raw.Email
	if email == "" {
		var emails []struct {
			Email    string `json:"email"`
			Primary  bool   `json:"primary"`
			Verified bool   `json:"verified"`
		}
		if err := getJSON(ctx, client, p.emailsURL, &emails); err == nil {
			for _, e := range emails {
				if e.Primary && e.Verified {
					email = e.Email
					break
				}
			}
		}
	}
	display := raw.Name
	if display == "" {
		display = raw.Login
	}
	return biz.OAuthProfile{
		Subject: strconv.FormatInt(raw.ID, 10), Issuer: "github",
		Display: display, Email: email,
	}, nil
}

type googleProvider struct {
	conf        *oauth2.Config
	log         *zap.Logger
	userInfoURL string
}

func (p *googleProvider) Name() string { return "google" }
func (p *googleProvider) AuthCodeURL(state, redirectURI string) string {
	c := *p.conf
	c.RedirectURL = redirectURI
	return c.AuthCodeURL(state, oauth2.AccessTypeOnline)
}

func (p *googleProvider) Exchange(ctx context.Context, code, redirectURI string) (biz.OAuthProfile, error) {
	c := *p.conf
	c.RedirectURL = redirectURI
	token, err := c.Exchange(ctx, code)
	if err != nil {
		return biz.OAuthProfile{}, err
	}
	client := c.Client(ctx, token)
	var raw struct {
		Sub   string `json:"sub"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if err := getJSON(ctx, client, p.userInfoURL, &raw); err != nil {
		return biz.OAuthProfile{}, err
	}
	return biz.OAuthProfile{Subject: raw.Sub, Issuer: "google", Display: raw.Name, Email: raw.Email}, nil
}

func getJSON(ctx context.Context, client *http.Client, url string, v any) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "user-center")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("oauth userinfo status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	return jsonx.Unmarshal(raw, v)
}
