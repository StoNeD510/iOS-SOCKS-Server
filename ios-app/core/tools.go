//go:build tools

// Keeps golang.org/x/mobile in go.mod; gomobile bind needs it.
package tools

import _ "golang.org/x/mobile/bind"
