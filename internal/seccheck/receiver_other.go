//go:build !linux || (!amd64 && !arm64)

package seccheck

import (
	"context"
	"fmt"
)

func (r Receiver) Serve(context.Context) error {
	return fmt.Errorf("SecCheck reception requires Linux amd64 or arm64")
}
