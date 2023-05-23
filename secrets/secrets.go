package secrets

import (
	"strings"
	"sync"
)

var lockSymmetric = &sync.RWMutex{}
var symmetric []byte

// GetSym reads symmetric key
func GetSym() []byte {
	lockSymmetric.RLock()
	secretCopy := symmetric
	lockSymmetric.RUnlock()
	return secretCopy
}

// SetSym is used to set secret used to sign tokens; this trims any
// spaces or newlines around the token string.
func SetSym(input string) {
	// Remove extra spaces added during parsing if input came from an unreliable
	// source like a text file that has an extra newline added accidentally.
	secretString := strings.Trim(input, " \n\t\r")
	lockSymmetric.Lock()
	symmetric = []byte(secretString)
	lockSymmetric.Unlock()
}

var lockAsym = &sync.RWMutex{}
var asymPvt, asymPub []byte

// SetAsym sets asymmetric secrets
// The JWT package can load x509 certificates directly
func SetAsym(pub, pvt string) {
	lockAsym.Lock()
	asymPvt = []byte(pvt)
	asymPub = []byte(pub)
	lockAsym.Unlock()
}

// GetAsymPub reads asymmetric public key
func GetAsymPub() []byte {
	lockAsym.RLock()
	rCopy := asymPub
	lockAsym.RUnlock()
	return rCopy
}

// GetAsymPvt reads asymmetric private key
func GetAsymPvt() []byte {
	lockAsym.RLock()
	rCopy := asymPvt
	lockAsym.RUnlock()
	return rCopy
}
