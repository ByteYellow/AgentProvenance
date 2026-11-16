// agentprov-verify verifies exported readers without a daemon or evidence store.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/byteyellow/agentprovenance/internal/buildinfo"
	"github.com/byteyellow/agentprovenance/internal/viewverify"
)

func main() {
	flags := flag.NewFlagSet("agentprov-verify", flag.ContinueOnError)
	policy := flags.String("trust-policy", "", "recipient-owned trust policy outside the evidence package")
	version := flags.Bool("version", false, "show verifier build version")
	flags.Usage = func() {
		fmt.Fprintln(flags.Output(), "Usage: agentprov-verify [--trust-policy FILE] DIRECTORY_OR_ZIP")
		flags.PrintDefaults()
	}
	if err := flags.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		os.Exit(3)
	}
	if *version {
		fmt.Printf("agentprov-verify %s (%s)\n", buildinfo.Version, buildinfo.Commit)
		return
	}
	if flags.NArg() != 1 {
		flags.Usage()
		os.Exit(3)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	code, err := viewverify.Verify(ctx, flags.Arg(0), *policy, os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	os.Exit(code)
}
