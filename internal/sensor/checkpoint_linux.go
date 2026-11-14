//go:build linux && (amd64 || arm64)

package sensor

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

const eventCaptureBoundary = 0x7ffffffe

type kernelCheckpointer struct {
	request *ebpf.Map
	program *ebpf.Program
}

// The program is invoked explicitly, never attached to a network interface.
// Its marker shares the syscall/TLS ring, whose reservation order is global:
// https://docs.kernel.org/bpf/ringbuf.html
func newKernelCheckpointer(events *ebpf.Map) (*kernelCheckpointer, error) {
	request, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1})
	if err != nil {
		return nil, err
	}
	code := asm.Instructions{
		asm.StoreImm(asm.RFP, -4, 0, asm.Word),
		asm.LoadMapPtr(asm.R1, request.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -4),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "missing"),
		asm.LoadMem(asm.R8, asm.R0, 0, asm.DWord),
		asm.LoadMapPtr(asm.R1, events.FD()),
		asm.Mov.Imm(asm.R2, sensorEventBytes),
		asm.Mov.Imm(asm.R3, 0),
		asm.FnRingbufReserve.Call(),
		asm.JEq.Imm(asm.R0, 0, "full"),
		asm.Mov.Reg(asm.R6, asm.R0),
	}
	for offset := 0; offset < sensorEventBytes; offset += 8 {
		code = append(code, asm.StoreImm(asm.R6, int16(offset), 0, asm.DWord))
	}
	code = append(code,
		asm.StoreImm(asm.R6, 0, eventCaptureBoundary, asm.Word),
		asm.StoreMem(asm.R6, 88, asm.R8, asm.DWord),
		asm.FnKtimeGetNs.Call(),
		asm.StoreMem(asm.R6, 24, asm.R0, asm.DWord),
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.Mov.Imm(asm.R2, 2), // BPF_RB_FORCE_WAKEUP, including an otherwise idle ring
		asm.FnRingbufSubmit.Call(),
		asm.Mov.Imm(asm.R0, 0), asm.Return(),
		asm.Mov.Imm(asm.R0, 1).WithSymbol("full"), asm.Return(),
		asm.Mov.Imm(asm.R0, 2).WithSymbol("missing"), asm.Return(),
	)
	program, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "ap_checkpoint", Type: ebpf.SocketFilter,
		License: "Apache-2.0", Instructions: code})
	if err != nil {
		request.Close()
		return nil, err
	}
	return &kernelCheckpointer{request, program}, nil
}

func (k *kernelCheckpointer) close() {
	k.program.Close()
	k.request.Close()
}

func (k *kernelCheckpointer) inject(ctx context.Context, sequence uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := k.request.Update(uint32(0), sequence, ebpf.UpdateAny); err != nil {
		return err
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		result, err := k.program.Run(&ebpf.RunOptions{Data: make([]byte, 64), Repeat: 1})
		if err != nil {
			return fmt.Errorf("inject sensor checkpoint: %w", err)
		}
		if result == 0 {
			return nil
		}
		if result != 1 {
			return fmt.Errorf("sensor checkpoint request missing")
		}
		timer := time.NewTimer(time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
