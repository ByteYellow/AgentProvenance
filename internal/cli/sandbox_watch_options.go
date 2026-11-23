package cli

import (
	"github.com/spf13/cobra"
	"time"
)

type watchOptions struct {
	namespace, nodeName, kubeconfig, master, selector, runAnnotation, runPrefix string
	resync, reportInterval, runFor                                              time.Duration
	workers, maxRetries                                                         int
	jsonOut                                                                     bool
}

func sandboxWatchCmd(dataDir *string) *cobra.Command {
	var opts watchOptions
	cmd := &cobra.Command{
		Use:   "watch",
		Short: "watch this node's pods and maintain passive cgroup scope bindings",
		Long: "A lightweight client-go informer controller. It List/Watches pods scheduled on one node, " +
			"creates passive bindings for running and recently terminated containers, closes replaced bindings after " +
			"container restart, and closes all pod bindings on deletion. It owns scope attribution only; " +
			"agentprov-sensor and telemetry ingest remain the independent data plane.",
		RunE: func(c *cobra.Command, _ []string) error { return runSandboxWatch(c, dataDir, opts) },
	}
	cmd.Flags().StringVar(&opts.namespace, "namespace", "", "watch one namespace; empty watches all namespaces")
	cmd.Flags().StringVar(&opts.nodeName, "node", "", "Kubernetes node name; defaults to NODE_NAME or hostname")
	cmd.Flags().StringVar(&opts.selector, "selector", "", "optional Kubernetes label selector for observed pods")
	cmd.Flags().StringVar(&opts.kubeconfig, "kubeconfig", "", "kubeconfig path; empty uses in-cluster config, then normal loading rules")
	cmd.Flags().StringVar(&opts.master, "master", "", "Kubernetes API server override")
	cmd.Flags().StringVar(&opts.runAnnotation, "run-annotation", "agentprov.io/run", "pod annotation containing the target run id")
	cmd.Flags().StringVar(&opts.runPrefix, "auto-run-prefix", "auto-", "run id prefix when the pod has no run annotation")
	cmd.Flags().DurationVar(&opts.resync, "resync", 10*time.Minute, "full informer resync interval")
	cmd.Flags().DurationVar(&opts.reportInterval, "report-interval", 30*time.Second, "human status report interval; 0 disables periodic reports")
	cmd.Flags().DurationVar(&opts.runFor, "run-for", 0, "stop after this duration; 0 runs until interrupted")
	cmd.Flags().IntVar(&opts.workers, "workers", 2, "reconcile workers")
	cmd.Flags().IntVar(&opts.maxRetries, "max-retries", 5, "rate-limited retries per pod event")
	cmd.Flags().BoolVar(&opts.jsonOut, "json", false, "emit the final machine-readable controller report")
	return cmd
}
