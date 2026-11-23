//go:build !agentprov_tools

package node

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/byteyellow/agentprovenance/internal/companion"
)

type DockerRuntime struct{}

func NewDockerRuntime() (*DockerRuntime, error) { return &DockerRuntime{}, nil }
func (*DockerRuntime) ComponentError() error    { _, err := companion.Path(); return err }
func (*DockerRuntime) Close() error             { return nil }

func callDocker(ctx context.Context, req dockerRequest, stdout, stderr io.Writer) (reply dockerReply, err error) {
	path, err := companion.Path()
	if err != nil {
		return reply, err
	}
	body, err := json.Marshal(req)
	if err != nil {
		return reply, err
	}
	r, w, err := os.Pipe()
	if err != nil {
		return reply, err
	}
	defer r.Close()
	cmd := exec.CommandContext(ctx, path, "internal", "docker-runtime-v1")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = bytes.NewReader(body), stdout, stderr
	cmd.ExtraFiles = []*os.File{w}
	err = cmd.Start()
	w.Close()
	if err != nil {
		return reply, err
	}
	decode := json.NewDecoder(io.LimitReader(r, 1<<20)).Decode(&reply)
	r.Close()
	if err = cmd.Wait(); err != nil {
		return reply, fmt.Errorf("Docker tools process: %w", err)
	}
	if decode != nil {
		return reply, fmt.Errorf("read Docker tools result: %w", decode)
	}
	if reply.Version != 1 {
		return reply, errors.New("unsupported Docker tools response")
	}
	if reply.Error != "" {
		return reply, errors.New(reply.Error)
	}
	return reply, nil
}

func (*DockerRuntime) CreateSession(req CreateSessionRequest) (string, error) {
	r, err := callDocker(context.Background(), dockerRequest{Operation: "create", Create: &req}, nil, nil)
	return r.Container, err
}
func (d *DockerRuntime) Exec(id string, args []string, stream bool) (ExecResult, error) {
	if stream {
		return d.ExecWithWriters(id, args, os.Stdout, os.Stderr)
	}
	return d.ExecWithWriters(id, args, nil, nil)
}
func (*DockerRuntime) ExecWithWriters(id string, args []string, out, errs io.Writer) (ExecResult, error) {
	r, err := callDocker(context.Background(), dockerRequest{Operation: "exec", Container: id, Command: args}, out, errs)
	return r.Exec, err
}
func (*DockerRuntime) Interrupt(id string) error {
	_, err := callDocker(context.Background(), dockerRequest{Operation: "interrupt", Container: id}, nil, nil)
	return err
}
func (*DockerRuntime) Stop(id string) error {
	_, err := callDocker(context.Background(), dockerRequest{Operation: "stop", Container: id}, nil, nil)
	return err
}
func (*DockerRuntime) Remove(id string) error {
	_, err := callDocker(context.Background(), dockerRequest{Operation: "remove", Container: id}, nil, nil)
	return err
}
func (*DockerRuntime) SetCPUWeight(ctx context.Context, id string, weight int64) error {
	_, err := callDocker(ctx, dockerRequest{Operation: "weight", Container: id, Weight: weight}, nil, nil)
	return err
}
