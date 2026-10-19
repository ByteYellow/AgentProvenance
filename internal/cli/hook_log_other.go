//go:build !darwin && !linux

package cli

import "fmt"

func appendHookLog(string, []byte, int64) error {
	return fmt.Errorf("hook log capture requires Linux or macOS")
}
