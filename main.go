package vaultWrapper

import (
	"errors"
	"fmt"
	"github.com/hashicorp/vault/api"
	"net/http"
	"regexp"
	"strconv"
)

type (
	Client struct {
		*api.Client
	}

	Error struct {
		err        error
		codeStatus int
	}
)

func (e *Error) Error() string {
	return e.err.Error()
}

func (e *Error) CodeStatus() int {
	return e.codeStatus
}

func NewError(code int, err error) *Error {
	return &Error{err: err, codeStatus: code}
}

// NewClient return a new client
func NewClient(address, token string) (*Client, error) {
	client, err := api.NewClient(&api.Config{Address: address})
	if err != nil {
		return nil, err
	}

	client.SetToken(token)

	wrapperClient := &Client{Client: client}

	return wrapperClient, nil

}

func (v *Client) SaveAndReadSecret(path string, secret map[string]interface{}) (*api.Secret, error) {
	data, err := v.Logical().Write(path, secret)
	if err != nil {
		return data, err
	}

	return data, err
}

func (v *Client) SaveSecret(path string, secret map[string]interface{}) error {
	_, err := v.Logical().Write(path, secret)
	if err != nil {
		return err
	}

	return nil
}

func (v *Client) DeleteSecret(path string) error {
	_, err := v.Logical().Delete(path)
	if err != nil {
		return err
	}

	return nil
}

func (v *Client) ReadSecret(path string) (map[string]interface{}, error) {
	secret, err := v.Logical().Read(path)
	if err != nil {
		return nil, err
	}

	// Vault API don't result error when secret is not found
	if secret == nil {
		return nil, NewError(404, fmt.Errorf("not_found.%v", path))
	}

	return secret.Data, nil
}

func (v *Client) SaveLogin(key string, password string) error {
	data := map[string]interface{}{
		"password": password,
	}
	_, err := v.Logical().Write(v.getUserpassPath(key), data)
	if err != nil {
		return err
	}
	return nil
}

func (v *Client) UpdatePassword(key string, password string) error {

	path := fmt.Sprintf("auth/userpass/users/%s/password", key)

	secret := map[string]interface{}{
		"password": password,
	}

	_, err := v.Logical().Write(path, secret)
	return err
}

func (v *Client) DeleteLogin(key string) error {
	_, err := v.Logical().Delete(v.getUserpassPath(key))
	if err != nil {
		return err
	}

	return nil
}

func (v *Client) Login(key string, password string) (string, error) {
	secret := map[string]interface{}{
		"password": password,
	}

	data, err := v.Logical().Write(v.getUserLoginPath(key), secret)
	if err != nil {
		statusCode, parsingErr := getStatusCode(err)
		if parsingErr != nil {
			return "", err
		}
		return "", NewError(statusCode, err)
	}

	token := data.Auth.ClientToken
	return token, err

}

func (v *Client) CheckToken(token string) (map[string]string, error) {
	payload := map[string]interface{}{
		"token": token,
	}

	data, err := v.Logical().Write("auth/token/lookup", payload)
	if err != nil {
		return map[string]string{}, err
	}

	if ttl, err := data.TokenTTL(); err != nil || ttl <= 0 {
		return map[string]string{}, NewError(http.StatusUnauthorized, errors.New("expired_token"))
	}

	return data.TokenMetadata()
}

func (v *Client) getUserpassPath(key string) string {
	return fmt.Sprintf("auth/userpass/users/%s", key)
}

func (v *Client) getSecretPath(key string) string {
	return fmt.Sprintf("secret/data/users/%s", key)
}

func (v *Client) getUserLoginPath(key string) string {
	return fmt.Sprintf("auth/userpass/login/%s", key)
}

func getStatusCode(err error) (int, error) {
	regex := regexp.MustCompile(`Code:\s(\d{3})`)
	match := regex.FindStringSubmatch(err.Error())
	if len(match) < 1 {
		return 0, errors.New("failed to parse vault return status code")
	}
	return strconv.Atoi(match[1])
}
