// Package auth verifies proxy users from the Proxy-Authorization header.
//
// Passwords are never stored in plain text: the users file holds a random
// salt and the hex SHA-256 of salt+password, and comparison is constant-time.
// (For production, a slow KDF such as bcrypt or Argon2 should replace SHA-256.)
package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// User is one entry in the users file.
type User struct {
	Salt  string `json:"salt"`
	Hash  string `json:"hash"`
	Group string `json:"group"`
}

// Store maps usernames to credentials.
type Store struct {
	users map[string]User
}

var ErrUnauthorized = errors.New("unauthorized")

// Load reads a JSON users file: {"alice": {"salt": "...", "hash": "...", "group": "..."}}.
func Load(file string) (*Store, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("read users: %w", err)
	}
	users := map[string]User{}
	if err := json.Unmarshal(data, &users); err != nil {
		return nil, fmt.Errorf("parse users: %w", err)
	}
	return &Store{users: users}, nil
}

// NewStore builds a store from an in-memory map.
func NewStore(users map[string]User) *Store { return &Store{users: users} }

// HashPassword returns hex(SHA-256(salt + password)).
func HashPassword(salt, password string) string {
	sum := sha256.Sum256([]byte(salt + password))
	return hex.EncodeToString(sum[:])
}

// Authenticate parses a "Basic <base64>" header and returns the username and group.
func (s *Store) Authenticate(header string) (string, string, error) {
	const prefix = "Basic "
	if !strings.HasPrefix(header, prefix) {
		return "", "", ErrUnauthorized
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(header, prefix))
	if err != nil {
		return "", "", ErrUnauthorized
	}
	name, pass, ok := strings.Cut(string(raw), ":")
	if !ok {
		return "", "", ErrUnauthorized
	}
	u, found := s.users[name]
	// Hash even for unknown users so timing does not reveal which names exist.
	got := HashPassword(u.Salt, pass)
	if subtle.ConstantTimeCompare([]byte(got), []byte(u.Hash)) != 1 || !found {
		return "", "", ErrUnauthorized
	}
	return name, u.Group, nil
}
