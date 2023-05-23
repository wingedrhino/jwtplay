package auth

import (
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/lestrrat/go-jwx/jwk"
	"github.com/pkg/errors"
)

// VerifyJWKS to verify token via JWKS
func VerifyJWKS(tokenString string, jwksURL string) (*jwt.Token, error) {

	var getKey = func(token *jwt.Token) (interface{}, error) {
		// TODO: cache response so we don't have to make a request every time
		// we want to verify a JWT
		set, err := jwk.FetchHTTP(jwksURL)
		if err != nil {
			return nil, errors.Wrapf(err, "error fetching JWKS from URL %s", jwksURL)
		}
		keyID, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New("expecting JWT header to have string kid")
		}
		if key := set.LookupKeyID(keyID); len(key) == 1 {
			key0, err := key[0].Materialize()
			err = errors.Wrapf(err, "unable to materialize key[0]")
			return key0, err
		}

		return nil, errors.New("unable to find key")
	}

	return jwt.Parse(tokenString, getKey)
}
