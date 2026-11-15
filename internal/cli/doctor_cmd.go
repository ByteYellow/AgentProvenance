package cli

import (
	"encoding/json"
	"os"

	"github.com/byteyellow/agentprovenance/internal/launch"
	"github.com/spf13/cobra"
)

func doctorCmd(dataDir *string) *cobra.Command {
	var (
		workdir      string
		dashAddr     string
		sensor       string
		jsonOut      bool
		remote       string
		runtimeCheck launch.RuntimePreflightOptions
	)
	cmd := &cobra.Command{
		Use:   "doctor [flags] [-- <agent command...>]",
		Short: "preflight launch readiness without running the agent",
		Long: "Check the host and requested agent command before `agentprov launch`: " +
			"agent binary, Claude Code hook injection, dashboard port, cgroup v2 " +
			"scope support, and kernel sensor capability. Use --remote-execution " +
			"to check a remote route, or --runtime to check local runtime dependencies.",
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			selfExe, _ := os.Executable()
			report := launch.Preflight(launch.Options{
				DataDir:         *dataDir,
				Command:         args,
				Workdir:         workdir,
				Dashboard:       true,
				DashboardAddr:   dashAddr,
				Sensor:          sensor,
				SelfExe:         selfExe,
				RemoteExecution: remote,
			})
			report.Checks = append(report.Checks, launch.RuntimePreflight(runtimeCheck)...)
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(report)
			}
			launch.PrintPreflightLocale(cmd.OutOrStdout(), report, commandLanguage(cmd))
			return nil
		},
	}
	cmd.Flags().StringVar(&workdir, "workdir", "", "agent working directory to check; defaults to current directory")
	cmd.Flags().StringVar(&dashAddr, "dashboard-addr", "127.0.0.1:7396", "dashboard listen address to test")
	cmd.Flags().StringVar(&sensor, "sensor", "auto", "kernel sensor mode to check: auto or off")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit machine-readable preflight report")
	cmd.Flags().StringVar(&remote, "remote-execution", "", "operator route to check against the executor without running a task")
	cmd.Flags().StringVar(&runtimeCheck.Runtime, "runtime", "", "optional local runtime to check: runsc or firecracker")
	cmd.Flags().StringVar(&runtimeCheck.Binary, "runtime-binary", "", "runtime executable; defaults to the runtime name on PATH")
	cmd.Flags().StringVar(&runtimeCheck.Rootfs, "runtime-rootfs", "", "selected runsc rootfs directory or Firecracker rootfs image")
	cmd.Flags().StringVar(&runtimeCheck.Kernel, "runtime-kernel", "", "selected Firecracker kernel image")
	return cmd
}
