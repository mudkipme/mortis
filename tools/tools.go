//go:build tools
// +build tools

package main

import (
	_ "github.com/bufbuild/buf/cmd/buf"
	_ "github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen"
)
