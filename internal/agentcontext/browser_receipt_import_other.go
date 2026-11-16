//go:build !linux && !darwin

package agentcontext

import (
	"context"
	"os"
)

func openBrowserOwnedDirectory(string) (*os.File, error) {
	return nil, browserImportError("platform_unsupported")
}

func checkBrowserOwnedDirectory(*os.File, string) error {
	return browserImportError("platform_unsupported")
}

func readBrowserOwnedFile(context.Context, *os.File, string, int64, int64) ([]byte, error) {
	return nil, browserImportError("platform_unsupported")
}
