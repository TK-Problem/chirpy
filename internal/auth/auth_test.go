package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
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

func TestMakeJWTAndValidateJWT(t *testing.T) {
	userID := uuid.New()
	secret := "my-very-secret-key"

	token, err := MakeJWT(userID, secret, time.Hour)
	if err != nil {
		t.Fatalf("MakeJWT() returned an error: %v", err)
	}
	if token == "" {
		t.Fatal("MakeJWT() returned an empty token")
	}

	gotID, err := ValidateJWT(token, secret)
	if err != nil {
		t.Fatalf("ValidateJWT() returned an error: %v", err)
	}
	if gotID != userID {
		t.Errorf("ValidateJWT() = %v, want %v", gotID, userID)
	}
}

func TestValidateJWTExpiredToken(t *testing.T) {
	userID := uuid.New()
	secret := "my-very-secret-key"

	// A negative duration puts ExpiresAt in the past, so the token is born expired.
	token, err := MakeJWT(userID, secret, -time.Hour)
	if err != nil {
		t.Fatalf("MakeJWT() returned an error: %v", err)
	}

	gotID, err := ValidateJWT(token, secret)
	if err == nil {
		t.Error("ValidateJWT() accepted an expired token, want an error")
	}
	if gotID != uuid.Nil {
		t.Errorf("ValidateJWT() = %v, want uuid.Nil on failure", gotID)
	}
}

func TestValidateJWTWrongSecret(t *testing.T) {
	userID := uuid.New()

	token, err := MakeJWT(userID, "secret-one", time.Hour)
	if err != nil {
		t.Fatalf("MakeJWT() returned an error: %v", err)
	}

	gotID, err := ValidateJWT(token, "secret-two")
	if err == nil {
		t.Error("ValidateJWT() accepted a token signed with a different secret, want an error")
	}
	if gotID != uuid.Nil {
		t.Errorf("ValidateJWT() = %v, want uuid.Nil on failure", gotID)
	}
}

func TestValidateJWTMalformedToken(t *testing.T) {
	cases := []struct {
		name  string
		token string
	}{
		{"not a jwt", "not.a.jwt"},
		{"empty string", ""},
		{"bearer prefix left on", "Bearer abc.def.ghi"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotID, err := ValidateJWT(c.token, "my-very-secret-key")
			if err == nil {
				t.Errorf("ValidateJWT(%q) returned no error, want one", c.token)
			}
			if gotID != uuid.Nil {
				t.Errorf("ValidateJWT() = %v, want uuid.Nil on failure", gotID)
			}
		})
	}
}

func TestMakeJWTDistinctUsers(t *testing.T) {
	secret := "my-very-secret-key"
	userA := uuid.New()
	userB := uuid.New()

	tokenA, err := MakeJWT(userA, secret, time.Hour)
	if err != nil {
		t.Fatalf("MakeJWT() returned an error: %v", err)
	}
	tokenB, err := MakeJWT(userB, secret, time.Hour)
	if err != nil {
		t.Fatalf("MakeJWT() returned an error: %v", err)
	}

	if tokenA == tokenB {
		t.Fatal("MakeJWT() produced identical tokens for different users")
	}

	gotA, err := ValidateJWT(tokenA, secret)
	if err != nil {
		t.Fatalf("ValidateJWT() returned an error: %v", err)
	}
	gotB, err := ValidateJWT(tokenB, secret)
	if err != nil {
		t.Fatalf("ValidateJWT() returned an error: %v", err)
	}

	if gotA != userA || gotB != userB {
		t.Errorf("tokens resolved to the wrong users: got %v and %v, want %v and %v", gotA, gotB, userA, userB)
	}
}
