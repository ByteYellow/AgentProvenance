//go:build !linux && !darwin

package runtimeadapter

import "fmt"

func ValidateTrustedPath(string, bool) error {
	return fmt.Errorf("trusted runtime paths require Linux or macOS")
}
func ReadTrustedFile(string, int64) ([]byte, error) {
	return nil, fmt.Errorf("trusted runtime files require Linux or macOS")
}
func readTrustedTail(string, int64) ([]byte, error) {
	return nil, fmt.Errorf("trusted runtime files require Linux or macOS")
}

func readPrivatePID(string) ([]byte, error) {
	return nil, fmt.Errorf("runtime PID files require Linux or macOS")
}
