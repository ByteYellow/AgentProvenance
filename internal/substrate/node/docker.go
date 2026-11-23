//go:build agentprov_tools

package node

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/containerd/errdefs"
	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/client"
)

type DockerRuntime struct {
	Client *client.Client
}

func NewDockerRuntime() (*DockerRuntime, error) {
	opts := []client.Opt{client.FromEnv}
	if os.Getenv("DOCKER_HOST") == "" {
		if home, err := os.UserHomeDir(); err == nil {
			desktopSocket := filepath.Join(home, ".docker", "run", "docker.sock")
			if _, err := os.Stat(desktopSocket); err == nil {
				opts = append(opts, client.WithHost("unix://"+desktopSocket))
			}
		}
	}
	cli, err := client.New(opts...)
	if err != nil {
		return nil, err
	}
	return &DockerRuntime{Client: cli}, nil
}

func (r *DockerRuntime) ComponentError() error { return nil }
func (r *DockerRuntime) Close() error          { return r.Client.Close() }

func (r *DockerRuntime) CreateSession(req CreateSessionRequest) (string, error) {
	ctx := context.Background()
	if req.Image == "" {
		return "", fmt.Errorf("task image is required")
	}
	hostCfg := buildHostConfig(req)
	cfg := buildContainerConfig(req)
	options := client.ContainerCreateOptions{Config: cfg, HostConfig: hostCfg, Name: "agentprov-" + req.SessionID}
	resp, err := r.Client.ContainerCreate(ctx, options)
	if err != nil {
		if !isNoSuchImage(err) {
			return "", err
		}
		pull, pullErr := r.Client.ImagePull(ctx, req.Image, client.ImagePullOptions{})
		if pullErr != nil {
			return "", pullErr
		}
		if err := pull.Wait(ctx); err != nil {
			return "", err
		}
		resp, err = r.Client.ContainerCreate(ctx, options)
		if err != nil {
			return "", err
		}
	}
	if _, err := r.Client.ContainerStart(ctx, resp.ID, client.ContainerStartOptions{}); err != nil {
		return "", err
	}
	return resp.ID, nil
}

func buildContainerConfig(req CreateSessionRequest) *container.Config {
	cfg := &container.Config{
		Image: req.Image, User: req.User, WorkingDir: "/workspace",
		Tty: false, OpenStdin: true, Cmd: []string{"sleep", "infinity"},
		Labels: map[string]string{
			"agentprov.session_id": req.SessionID,
			"agentprov.lease_id":   req.LeaseID,
			"agentprov.run_id":     req.RunID,
		},
	}
	// With all capabilities dropped, container root cannot bypass the host
	// workspace's ownership. Match its creator instead of weakening permissions.
	if cfg.User == "" && os.Geteuid() >= 0 && os.Getegid() >= 0 {
		cfg.User = fmt.Sprintf("%d:%d", os.Geteuid(), os.Getegid())
		if os.Geteuid() != 0 {
			// Arbitrary host UIDs may have no passwd entry or writable image home.
			cfg.Env = []string{"HOME=/tmp"}
		}
	}
	return cfg
}

// Drop capabilities and block privilege gains while keeping the workspace writable.
func buildHostConfig(req CreateSessionRequest) *container.HostConfig {
	hostCfg := &container.HostConfig{
		CapDrop:     []string{"ALL"},
		SecurityOpt: []string{"no-new-privileges"},
		Mounts: []mount.Mount{{
			Type:   mount.TypeBind,
			Source: req.WorkspaceHostPath,
			Target: "/workspace",
		}},
	}
	if req.DockerNetworkName != "" {
		hostCfg.NetworkMode = container.NetworkMode(req.DockerNetworkName)
	}
	if req.MemoryMB > 0 {
		hostCfg.Resources.Memory = req.MemoryMB * 1024 * 1024
	}
	return hostCfg
}

func (r *DockerRuntime) Exec(containerID string, command []string, stream bool) (ExecResult, error) {
	stdout := io.Discard
	stderr := io.Discard
	if stream {
		stdout = os.Stdout
		stderr = os.Stderr
	}
	return r.ExecWithWriters(containerID, command, stdout, stderr)
}

func (r *DockerRuntime) ExecWithWriters(containerID string, command []string, stdout, stderr io.Writer) (ExecResult, error) {
	ctx := context.Background()
	resp, err := r.Client.ExecCreate(ctx, containerID, client.ExecCreateOptions{
		Cmd:          command,
		AttachStdout: true,
		AttachStderr: true,
		WorkingDir:   "/workspace",
	})
	if err != nil {
		return ExecResult{}, err
	}
	attach, err := r.Client.ExecAttach(ctx, resp.ID, client.ExecAttachOptions{})
	if err != nil {
		return ExecResult{ExecID: resp.ID}, err
	}
	defer attach.Close()
	if stdout != nil || stderr != nil {
		if stdout == nil {
			stdout = io.Discard
		}
		if stderr == nil {
			stderr = io.Discard
		}
		_, err = stdcopy.StdCopy(stdout, stderr, attach.Reader)
	} else {
		_, err = io.Copy(io.Discard, attach.Reader)
	}
	if err != nil {
		return ExecResult{ExecID: resp.ID}, err
	}
	inspect, err := r.Client.ExecInspect(ctx, resp.ID, client.ExecInspectOptions{})
	if err != nil {
		return ExecResult{ExecID: resp.ID}, err
	}
	result := ExecResult{ExecID: resp.ID, ExitCode: inspect.ExitCode}
	if inspect.ExitCode != 0 {
		return result, fmt.Errorf("exec exited with code %d", inspect.ExitCode)
	}
	return result, nil
}

func (r *DockerRuntime) Interrupt(containerID string) error {
	_, err := r.Client.ContainerKill(context.Background(), containerID, client.ContainerKillOptions{Signal: "SIGTERM"})
	return err
}

func (r *DockerRuntime) SetCPUWeight(ctx context.Context, containerID string, weight int64) error {
	if weight < 2 {
		weight = 2
	}
	if weight > 262144 {
		weight = 262144
	}
	_, err := r.Client.ContainerUpdate(ctx, containerID, client.ContainerUpdateOptions{
		Resources: &container.Resources{
			CPUShares: weight,
		},
	})
	return err
}

func (r *DockerRuntime) Stop(containerID string) error {
	_, err := r.Client.ContainerStop(context.Background(), containerID, client.ContainerStopOptions{})
	if errdefs.IsNotFound(err) {
		return nil
	}
	return err
}

func (r *DockerRuntime) Remove(containerID string) error {
	_, err := r.Client.ContainerRemove(context.Background(), containerID, client.ContainerRemoveOptions{Force: true})
	if errdefs.IsNotFound(err) {
		return nil
	}
	return err
}

func isNoSuchImage(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "No such image") || strings.Contains(msg, "not found")
}
