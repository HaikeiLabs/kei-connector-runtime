// Package errdef holds the secret-store error sentinels shared by the store
// registry and its backend packages. Backends live in subpackages that the
// registry imports, so a backend cannot import the registry package back; the
// sentinels live here, a leaf both sides import, and errors.Is matches them
// across the package boundary.
package errdef

import "errors"

var (
	// ErrNotFound reports that the reference names no readable secret.
	ErrNotFound = errors.New("secret not found")
	// ErrUnavailable reports that the backend is unknown, could not be built,
	// or failed the call.
	ErrUnavailable = errors.New("secret store unavailable")
	// ErrExists reports a write that conflicts with an existing secret.
	ErrExists = errors.New("secret already exists")
)
