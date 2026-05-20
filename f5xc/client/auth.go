package client

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

type Authenticator interface {
	Apply(req *http.Request) error
}

type TransportProvider interface {
	Transport() *http.Transport
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

type CertAuth struct {
	transport *http.Transport
}

func NewCertAuth(p12Data []byte, password string) (*CertAuth, error) {
	if len(p12Data) == 0 {
		return nil, errors.New("f5xc: P12 certificate data is empty")
	}

	privateKey, leafCert, caCerts, err := pkcs12.DecodeChain(p12Data, password)
	if err != nil {
		return nil, errors.New("f5xc: failed to decode P12 certificate: " + err.Error())
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{leafCert.Raw},
		PrivateKey:  privateKey,
	}
	for _, ca := range caCerts {
		tlsCert.Certificate = append(tlsCert.Certificate, ca.Raw)
	}

	caPool, err := x509.SystemCertPool()
	if err != nil {
		caPool = x509.NewCertPool()
	}
	for _, ca := range caCerts {
		caPool.AddCert(ca)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		RootCAs:      caPool,
	}

	return &CertAuth{
		transport: &http.Transport{TLSClientConfig: tlsConfig},
	}, nil
}

func (a *CertAuth) Apply(req *http.Request) error {
	return nil
}

func (a *CertAuth) Transport() *http.Transport {
	return a.transport
}
