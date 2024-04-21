package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"net/http"
	"sync"

	"github.com/thedonutfactory/go-tfhe/core"
	"github.com/thedonutfactory/go-tfhe/gates"
	"github.com/zambozoo/homomorphic-authentication/crypto"
)

var (
	errUserExists         = errors.New("user already exists")
	errUserDoesNotExist   = errors.New("user doesn't exist")
	errInvalidCredentials = errors.New("invalid credentials")
)

type (
	// User is a user's profile for logging in
	User struct {
		Username        string
		EncryptedSecret gates.Ctxt
		SecretHash      []byte
		Salt            []byte
	}

	// Server is a web server that permits signups and logins
	Server struct {
		saltByteLen  int
		port         uint16
		userDatabase map[string]User
		userDBMu     sync.Mutex
	}

	// FirstLogInResponse is the response to a first login request
	FirstLogInResponse struct {
		EncryptedMutatedSecret gates.Ctxt
	}
)

// NewServer starts and returns a new server at a port with a salt byte length
func NewServer(saltByteLen int, port uint16) *Server {
	s := &Server{
		saltByteLen:  saltByteLen,
		port:         port,
		userDatabase: map[string]User{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/sign-up", s.SignUpHandler)
	mux.HandleFunc("/login-1", s.FirstLoginHandler)
	mux.HandleFunc("/login-2", s.SecondLoginHandler)

	go func() {
		if err := http.ListenAndServe(":"+fmt.Sprintf("%d", s.port), mux); err != nil {
			panic(err)
		}
	}()

	return s
}

// makeEncryptedMutation returns an encrypted number such that the upper and lower halves share the same bits
// This is done without knowing what the value is
func makeEncryptedMutation(packet *crypto.Packet, encryptedPayload gates.Ctxt) gates.Ctxt {
	randomPayload := make(gates.Ctxt, len(encryptedPayload))
	randByteStream := crypto.MakeRandByteStream()
	for i := 0; i < len(encryptedPayload)/2; i++ {
		f := func(a *core.LweSample) *core.LweSample {
			return a
		}
		if randByteStream.NextByte()%2 == 0 {
			f = packet.Pub().Not
		}

		randomPayload[i] = f(encryptedPayload[0])
		randomPayload[i+len(encryptedPayload)/2] = f(encryptedPayload[0])
	}

	return randomPayload
}

// xorBytes returns a slice of bytes that is the XOR of the input values
func xorBytes(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("expected equal number of bytes")
	}

	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}

	return result
}

// SignUpHandler handles sign up requests
// New users are registered and return a 2XX status
// Malformed requests and existing users return a 4XX status
// Hashing errors return a 5XX status
func (s *Server) SignUpHandler(w http.ResponseWriter, req *http.Request) {
	var signUpRequest SignUpRequest
	if err := json.NewDecoder(req.Body).Decode(&signUpRequest); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.userDBMu.Lock()
	_, ok := s.userDatabase[signUpRequest.Username]
	s.userDBMu.Unlock()
	if ok {
		http.Error(w, errUserExists.Error(), http.StatusBadRequest)
		return
	}

	salt := make([]byte, s.saltByteLen)
	if _, err := rand.Read(salt); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	hash64 := fnv.New64()
	hashBytes := append(salt, signUpRequest.Secret...)
	if _, err := hash64.Write(hashBytes); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.userDBMu.Lock()
	s.userDatabase[signUpRequest.Username] = User{
		Username:        signUpRequest.Username,
		EncryptedSecret: signUpRequest.EncryptedSecret,
		SecretHash:      hash64.Sum(nil),
		Salt:            salt,
	}
	s.userDBMu.Unlock()

	w.WriteHeader(http.StatusOK)
}

// FirstLoginHandler handles first login requests
// Existing users return the cryptographic challenge and a 2XX status
// Malformed requests and nonexistent users return a 4XX status
func (s *Server) FirstLoginHandler(w http.ResponseWriter, req *http.Request) {
	var firstLogInRequest FirstLogInRequest
	if err := json.NewDecoder(req.Body).Decode(&firstLogInRequest); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.userDBMu.Lock()
	user, ok := s.userDatabase[firstLogInRequest.Username]
	s.userDBMu.Unlock()
	if !ok {
		http.Error(w, errUserDoesNotExist.Error(), http.StatusBadRequest)
		return
	}

	serverPacket := crypto.MakePublicPacket(firstLogInRequest.PublicKey)
	randomPayload := makeEncryptedMutation(serverPacket, user.EncryptedSecret)
	firstLogInResponse := &FirstLogInResponse{
		EncryptedMutatedSecret: serverPacket.Xor(randomPayload, user.EncryptedSecret),
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(firstLogInResponse)
}

// SecondLoginHandler handles second login requests
// Successful authentications return a 2XX status
// Malformed requests, nonexistent users, and authenticaiton failures return a 4XX status
// Hashing errors return a 5XX status
func (s *Server) SecondLoginHandler(w http.ResponseWriter, req *http.Request) {
	var secondLogInRequest SecondLogInRequest
	if err := json.NewDecoder(req.Body).Decode(&secondLogInRequest); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.userDBMu.Lock()
	user, ok := s.userDatabase[secondLogInRequest.Username]
	s.userDBMu.Unlock()
	if !ok {
		http.Error(w, errUserDoesNotExist.Error(), http.StatusBadRequest)
		return
	}

	hash64 := fnv.New64()
	hashBytes := append(user.Salt, secondLogInRequest.Secret...)
	if _, err := hash64.Write(hashBytes); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	secretHash := hash64.Sum(nil)

	if !bytes.Equal(secretHash, user.SecretHash) {
		http.Error(w, errInvalidCredentials.Error(), http.StatusForbidden)
		return
	}

	w.WriteHeader(http.StatusOK)
}
