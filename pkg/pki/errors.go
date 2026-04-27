package pki

import "errors"

// ErrNotSupported is returned when a PKI operation is not supported by the provider.
// Callers should check for this sentinel to distinguish unsupported operations
// from real failures.
//
//	if errors.Is(err, pki.ErrNotSupported) { ... }
var ErrNotSupported = errors.New("operation not supported by this provider")
