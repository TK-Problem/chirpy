package auth

import (
	"strings"
	"testing"
)

func TestHashPassword(t *testing.T) {
	password := "correctHorseBatteryStaple"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() returned an error: %v", err)
	}
	if hash == password {
		t.Error("HashPassword() returned the plaintext password")
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("HashPassword() = %q, want a hash starting with $argon2id$", hash)
	}
}

func TestHashPasswordIsSalted(t *testing.T) {
	password := "correctHorseBatteryStaple"

	first, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() returned an error: %v", err)
	}
	second, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() returned an error: %v", err)
	}

	if first == second {
		t.Error("hashing the same password twice produced identical hashes, want a random salt each time")
	}
}

func TestCheckPasswordHash(t *testing.T) {
	password1 := "correctHorseBatteryStaple"
	password2 := "anotherPassword"

	hash1, err := HashPassword(password1)
	if err != nil {
		t.Fatalf("HashPassword() returned an error: %v", err)
	}
	hash2, err := HashPassword(password2)
	if err != nil {
		t.Fatalf("HashPassword() returned an error: %v", err)
	}

	cases := []struct {
		name      string
		password  string
		hash      string
		wantMatch bool
	}{
		{"correct password", password1, hash1, true},
		{"wrong password", "notThePassword", hash1, false},
		{"other user's hash", password1, hash2, false},
		{"empty password", "", hash1, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			match, err := CheckPasswordHash(c.password, c.hash)
			if err != nil {
				t.Fatalf("CheckPasswordHash() returned an error: %v", err)
			}
			if match != c.wantMatch {
				t.Errorf("CheckPasswordHash() = %v, want %v", match, c.wantMatch)
			}
		})
	}
}

// Users created before passwords existed carry the column default, which is not
// a valid encoded hash. They must error out rather than match anything.
func TestCheckPasswordHashMalformedHash(t *testing.T) {
	match, err := CheckPasswordHash("anyPassword", "unset")
	if err == nil {
		t.Error("CheckPasswordHash() with a malformed hash returned no error, want one")
	}
	if match {
		t.Error("CheckPasswordHash() matched against a malformed hash")
	}
}
