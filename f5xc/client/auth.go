package client

import (
	"errors"
	"net/http"
)

type Authenticator interface {
	Apply(req *http.Request) error
}

type TokenAuth struct {
	Token string
}

func (a *TokenAuth) Apply(req *http.Request) error {
	if a.Token == "" {
		return errors.New("f5xc: API token is empty")
	}
	req.Header.Set("Authorization", "APIToken "+a.Token)
	return nil
}
