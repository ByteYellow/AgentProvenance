//go:build agentprov_tools

package node

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
)

func ServeDockerCall(in io.Reader, out, stderr, result io.Writer) error {
	var req dockerRequest
	reply := dockerReply{Version: 1}
	err := json.NewDecoder(io.LimitReader(in, 4<<20)).Decode(&req)
	if err == nil {
		var d *DockerRuntime
		d, err = NewDockerRuntime()
		if err == nil {
			defer d.Close()
			switch req.Operation {
			case "create":
				if req.Create == nil {
					err = fmt.Errorf("missing Docker create request")
				} else {
					reply.Container, err = d.CreateSession(*req.Create)
				}
			case "exec":
				reply.Exec, err = d.ExecWithWriters(req.Container, req.Command, out, stderr)
			case "interrupt":
				err = d.Interrupt(req.Container)
			case "stop":
				err = d.Stop(req.Container)
			case "remove":
				err = d.Remove(req.Container)
			case "weight":
				err = d.SetCPUWeight(context.Background(), req.Container, req.Weight)
			default:
				err = fmt.Errorf("unknown Docker tools operation %q", req.Operation)
			}
		}
	}
	if err != nil {
		reply.Error = err.Error()
	}
	return json.NewEncoder(result).Encode(reply)
}
