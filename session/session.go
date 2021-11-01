// Package session provides handles creation of a Salesforce session
package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/g8rswimmer/go-sfdc"
	"github.com/g8rswimmer/go-sfdc/credentials"
)

// Session is the authentication response.  This is used to generate the
// authroization header for the Salesforce API calls.
type Session struct {
	response *sessionPasswordResponse
	config   sfdc.Configuration
}

// Clienter interface provides the HTTP client used by the
// the resources.
type Clienter interface {
	Client() *http.Client
}

// InstanceFormatter is the session interface that
// formaters the session instance information used
// by the resources.
//
// InstanceURL will return the Salesforce instance.
//
// AuthorizationHeader will add the authorization to the
// HTTP request's header.
type InstanceFormatter interface {
	InstanceURL() string
	AuthorizationHeader(*http.Request)
	Clienter
}

// ServiceFormatter is the session interface that
// formats the session for service resources.
//
// ServiceURL provides the service URL for resources to
// user.
type ServiceFormatter interface {
	InstanceFormatter
	ServiceURL() string
}

type sessionPasswordResponse struct {
	AccessToken string `json:"access_token"`
	InstanceURL string `json:"instance_url"`
	ID          string `json:"id"`
	TokenType   string `json:"token_type"`
	IssuedAt    string `json:"issued_at"`
	Signature   string `json:"signature"`
}

const oauthEndpoint = "/services/oauth2/token"

// Open is used to authenticate with Salesforce and open a session.  The user will need to
// supply the proper credentials and a HTTP client.
func Open(config sfdc.Configuration) (*Session, error) {
	if config.Credentials == nil {
		return nil, errors.New("session: configuration crendentials can not be nil")
	}
	if config.Client == nil {
		return nil, errors.New("session: configuration client can not be nil")
	}
	if config.Version <= 0 {
		return nil, errors.New("session: configuration version can not be less than zero")
	}
	request, err := passwordSessionRequest(config.Credentials)

	if err != nil {
		return nil, err
	}

	response, err := passwordSessionResponse(request, config.Client)
	if err != nil {
		return nil, err
	}

	session := &Session{
		response: response,
		config:   config,
	}

	return session, nil
}

func passwordSessionRequest(creds *credentials.Credentials) (*http.Request, error) {

	oauthURL := creds.URL() + oauthEndpoint

	body, err := creds.Retrieve()
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequest(http.MethodPost, oauthURL, body)

	if err != nil {
		return nil, err
	}

	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Add("Accept", "application/json")
	return request, nil
}

func passwordSessionResponse(request *http.Request, client *http.Client) (*sessionPasswordResponse, error) {
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("session response error: %d %s", response.StatusCode, response.Status)
	}
	decoder := json.NewDecoder(response.Body)
	defer response.Body.Close()

	var sessionResponse sessionPasswordResponse
	err = decoder.Decode(&sessionResponse)
	if err != nil {
		return nil, err
	}

	return &sessionResponse, nil
}

// InstanceURL will retuern the Salesforce instance
// from the session authentication.
func (session *Session) InstanceURL() string {
	return session.response.InstanceURL
}

// ServiceURL will return the Salesforce instance for the
// service URL.
func (session *Session) ServiceURL() string {
	return fmt.Sprintf("%s/services/data/v%d.0", session.response.InstanceURL, session.config.Version)
}

// AuthorizationHeader will add the authorization to the
// HTTP request's header.
func (session *Session) AuthorizationHeader(request *http.Request) {
	auth := fmt.Sprintf("%s %s", session.response.TokenType, session.response.AccessToken)
	request.Header.Add("Authorization", auth)
}

// Client returns the HTTP client to be used in APIs calls.
func (session *Session) Client() *http.Client {
	return session.config.Client
}

const introspectUrl = "/services/oauth2/introspect"

type introspectCallResponse struct {
	Active    bool   `json:"active"`
	Exp       int    `json:"exp"`
	Iat       int    `json:"iat"`
	Nfb       int    `json:"nfb"`
	Scope     string `json:"scope"`
	Sub       string `json:"sub"`
	TokenType string `json:"token_type"`
	Username  string `json:"username"`
}

func sessionIntrospectRequest(session *Session) (*http.Request, error) {
	// build request parameters from session
	form := url.Values{}
	form.Add("token", session.response.AccessToken)
	form.Add("token_type_hint", "access_token")
	form.Add("client_id", session.config.Credentials.ClientId())
	form.Add("client_secret", session.config.Credentials.ClientSecret())
	body := strings.NewReader(form.Encode())

	// prepare the request url
	requestUrl := session.InstanceURL() + introspectUrl

	request, err := http.NewRequest(http.MethodPost, requestUrl, body)
	if err != nil {

		return nil, err
	}

	// add the headers as expected by SalesForce
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Add("Accept", "application/json")

	return request, nil
}

func sessionIntrospectResponse(request *http.Request, client *http.Client) (*introspectCallResponse, error) {
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("session response error: %d %s", response.StatusCode, response.Status)
	}
	decoder := json.NewDecoder(response.Body)
	defer response.Body.Close()
	var sessionResponse introspectCallResponse
	err = decoder.Decode(&sessionResponse)
	return &sessionResponse, err
}

func (session *Session) IsActive() bool {
	request, err := sessionIntrospectRequest(session)
	if err != nil {
		return false
	}
	response, err := sessionIntrospectResponse(request, session.Client())
	if err != nil {
		return false
	}
	return response.Active
}
