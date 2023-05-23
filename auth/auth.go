package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/mahtuag/jwtplay/secrets"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
)

// TokenGetter is a function that accepts a jwt.Claims object and returns a signed
// token as a string and an error if any
type TokenGetter func(jwt.Claims) (string, error)

// GetToken accepts a claims object and signs it with the algorithm provided via
// the alg field.
func GetToken(claims jwt.Claims, alg string) (string, error) {
	switch alg {
	case "RS256":
		return GetTokenRS256(claims)
	case "HS256":
		return GetTokenHS256(claims)
	default:
		return "", errors.Errorf("Invalid algorithm '%s'. Valid values: 'RS256', 'HS256", alg)
	}
}

// GetTokenHS256 returns a JWT token created from the provided claims object
func GetTokenHS256(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(secrets.GetSym())
	err = errors.Wrapf(err, "error signing claims via HS256: %v", claims)
	return tokenString, err
}

// GetTokenRS256 returns a JWT token created from the provided claims object
func GetTokenRS256(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(secrets.GetAsymPub())
	err = errors.Wrapf(err, "error signing claims via RS256: %v", claims)
	return tokenString, err
}

// ValidateToken parses a JWT token, checks it for validity and returns a
// `*jwt.Token` object
func ValidateToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		switch token.Method.(type) {
		case *jwt.SigningMethodHMAC:
			return secrets.GetSym(), nil
		case *jwt.SigningMethodRSA:
			pubKey, err := jwt.ParseRSAPublicKeyFromPEM(secrets.GetAsymPub())
			if err != nil {
				return nil, errors.Wrap(err, "Unable to parse RSA pubkey from PEM")
			}
			return pubKey, nil
		default:
			return nil, errors.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
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

// VerifyManualHS256 manually verifies that a JWT token is valid and returns the
// body in a DummyJSONClaims object
// This assumes that the token is a HS256 token
func VerifyManualHS256(tokenString string) error {
	parts, err := getParts(tokenString)
	if err != nil {
		return err
	}
	tokenToSign := parts[0] + "." + parts[1]
	h := hmac.New(sha256.New, secrets.GetSym())
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
