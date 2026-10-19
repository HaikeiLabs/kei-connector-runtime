package connectorruntime

import keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"

// Type aliases for types moved to runtime/.
type (
	AuthorizeResponse    = keiruntime.AuthorizeResponse
	AuthorizeOutput      = keiruntime.AuthorizeOutput
	CredentialResponse   = keiruntime.CredentialResponse
	CredentialDescriptor = keiruntime.CredentialDescriptor
)

// Error sentinel aliases.
var errCredentialBindingNotFound = keiruntime.ErrCredentialBindingNotFound
