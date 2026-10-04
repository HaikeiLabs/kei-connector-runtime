package connectorruntime

import keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"

// Type aliases for types moved to runtime/.
type (
	AuthorizeResponse    = keiruntime.AuthorizeResponse
	AuthorizeOutput      = keiruntime.AuthorizeOutput
	CredentialResponse   = keiruntime.CredentialResponse
	CredentialDescriptor = keiruntime.CredentialDescriptor
	OAuthTokenResponse   = keiruntime.OAuthTokenResponse
)

// Error sentinel aliases.
var (
	ErrEnrollmentRequired        = keiruntime.ErrEnrollmentRequired
	errCredentialBindingNotFound = keiruntime.ErrCredentialBindingNotFound
)
