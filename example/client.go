package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/thedonutfactory/go-tfhe/gates"
	"github.com/zambozoo/homomorphic-authentication/crypto"
)

type (
	// Client is a client for a signup and login service
	Client struct {
		Port           uint16
		messageByteLen int
		httpClient     *http.Client
	}

	// SignUpRequest is a request to sign up for a service
	SignUpRequest struct {
		Username        string     `json:"Username"`
		EncryptedSecret gates.Ctxt `json:"EncryptedSecret"`
		Secret          []byte     `json:"Secret"`
	}

	// FirstLogInRequest is a request to start logging into a service
	FirstLogInRequest struct {
		Username  string            `json:"Username"`
		PublicKey *crypto.PublicKey `json:"PublicKey"`
	}

	// SecondLogInRequest is a request to finish logging into a service
	SecondLogInRequest struct {
		Username string `json:"Username"`
		Secret   []byte `json:"Secret"`
	}
)

// NewClient returns a client to a service given a message length and port
func NewClient(messageByteLen int, port uint16) *Client {
	return &Client{
		Port:           port,
		messageByteLen: messageByteLen,
		httpClient:     http.DefaultClient,
	}
}

// baseURL returns the service's base url
func (c *Client) baseURL() string {
	return fmt.Sprintf("http://localhost:%d", c.Port)
}

// makeHTTPCall returns the response to an http call for a given method, url, and body
func (c *Client) makeHTTPCall(method, url string, body any) (*http.Response, error) {
	reqBody, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, url, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}

	return c.httpClient.Do(req)
}

// SignUp signs up a user in the service with a given username and password
func (c *Client) SignUp(username, password string) (bool, error) {
	byteStream := crypto.MakeByteStream([]byte(password))
	packet := crypto.MakePacket(byteStream)
	noise := make([]byte, c.messageByteLen) //randCryptoByteStream().nextBytes(c.messageByteLen)
	secret := crypto.MakeRandByteStream().NextBytes(c.messageByteLen)
	payload := append(noise, xorBytes(noise, secret)...)

	req := &SignUpRequest{
		Username:        username,
		EncryptedSecret: packet.Encrypt(payload),
		Secret:          secret,
	}
	fmt.Printf("Secret:\t\t\t%v\n", req.Secret)

	resp, err := c.makeHTTPCall(http.MethodPut, c.baseURL()+"/sign-up", req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK, nil
}

// LogIn logs a user into the service with a username and password
func (c *Client) LogIn(username, password string) (bool, error) {
	byteStream := crypto.MakeByteStream([]byte(password))
	packet := crypto.MakePacket(byteStream)
	firstReq := &FirstLogInRequest{
		Username:  username,
		PublicKey: crypto.MakePublicKey(packet.Pub()),
	}

	firstResp, err := c.makeHTTPCall(http.MethodPost, c.baseURL()+"/login-1", firstReq)
	if err != nil {
		return false, err
	}
	defer firstResp.Body.Close()

	var firstLogInResponse FirstLogInResponse
	if err := json.NewDecoder(firstResp.Body).Decode(&firstLogInResponse); err != nil {
		return false, err
	}

	mutatedSecret := packet.Decrypt(firstLogInResponse.EncryptedMutatedSecret)
	secondReq := &SecondLogInRequest{
		Username: username,
		Secret:   xorBytes(mutatedSecret[:c.messageByteLen], mutatedSecret[c.messageByteLen:]),
	}
	fmt.Printf("Decrypted Secret:\t%v\n", secondReq.Secret)

	secondResp, err := c.makeHTTPCall(http.MethodPost, c.baseURL()+"/login-2", secondReq)
	if err != nil {
		return false, err
	}
	defer secondResp.Body.Close()

	return secondResp.StatusCode == http.StatusOK, nil
}
