package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
)

var lock = &sync.RWMutex{}
var secret []byte

func readSecret() []byte {
	lock.RLock()
	secretCopy := secret
	lock.RUnlock()
	return secretCopy
}

// SetSecret is used to set secret used to sign tokens; this trims any spaces
// or newlines around the token string.
func SetSecret(input string) {
	// Remove extra spaces added during parsing if input came from an unreliable
	// source like a text file that has an extra newline added accidentally.
	secretString := strings.Trim(input, " \n\t\r")
	lock.Lock()
	secret = []byte(secretString)
	lock.Unlock()
}

// GetToken returns a JWT token created from the provided claims object
func GetToken(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(readSecret())
	err = errors.Wrapf(err, "error: SigningMethodHS256: unable to sign claims: %v", claims)
	return tokenString, err
}

// ParseToken parses a JWT token, checks it for validity and returns a
// *jwt.Token object
func ParseToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return readSecret(), nil
	})
	return token, errors.Wrap(err, "error: invalid token")
}

// VerifyEmail checks if token contains an "email" field and also an
// "email_verified" field (which is either `true` or `"true"`). I wrote this to
// checking that I am getting a token from a verified logged-in user from Auth0
// but left it here anyway.
func VerifyEmail(token *jwt.Token) error {
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		verified := claims["email_verified"]
		if verifiedBool, ok := verified.(bool); !(ok && verifiedBool) {
			// just in case we received email_verified as a string
			// this really shouldn't be an extra check
			if verifiedString, ok := verified.(string); !(ok && (verifiedString == "true")) {
				return errors.Errorf("email is not yet verified")
			}
		}
		emailClaim := claims["email"]
		if email, ok := emailClaim.(string); ok && (len(email) > 0) {
			return nil
		}
		return errors.New("Email is a must in token claims")
	}
	return errors.New("Invalid token")
}

func getParts(tokenString string) (parts []string, err error) {
	parts = strings.Split(tokenString, ".")
	if len(parts) != 3 {
		err = errors.New("token doesn't have 3 parts")
	}
	return
}

// VerifyManual manually verifies that a JWT token is valid and returns the
// body in a DummyJSONClaims object
func VerifyManual(tokenString string) error {
	parts, err := getParts(tokenString)
	if err != nil {
		return err
	}
	tokenToSign := parts[0] + "." + parts[1]
	h := hmac.New(sha256.New, readSecret())
	_, err = h.Write([]byte(tokenToSign))
	if err != nil {
		return errors.Wrap(err, "error writing data to HMAC function")
	}
	signedToken := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	if signedToken != parts[2] {
		return errors.New("error verifying token: provided signature doesn't match computed signature")
	}
	return nil
}

// ParseClaims parses the claims portion of a JWT token
func ParseClaims(tokenString string) (claims SimpleClaims, err error) {
	parts, err := getParts(tokenString)
	if err != nil {
		return
	}
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		err = errors.Wrap(err, "error decoding claims from base64")
		return
	}
	err = json.Unmarshal(claimsJSON, &claims)
	err = errors.Wrap(err, "error unmarshaling claims JSON")
	return
}
