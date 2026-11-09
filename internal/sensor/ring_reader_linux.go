//go:build linux && (amd64 || arm64)

package sensor

import (
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf/ringbuf"
)

func decodeSensorEvent(data []byte) (e sensorbpfSensorEvent, err error) {
	if len(data) != sensorEventBytes {
		return e, fmt.Errorf("invalid sensor record size %d, expected %d", len(data), sensorEventBytes)
	}
	e.Kind = binary.LittleEndian.Uint32(data[0:4])
	e.Pid = binary.LittleEndian.Uint32(data[4:8])
	e.Tid = binary.LittleEndian.Uint32(data[8:12])
	e.Ppid = binary.LittleEndian.Uint32(data[12:16])
	e.CgroupId = binary.LittleEndian.Uint64(data[16:24])
	e.KtimeNs = binary.LittleEndian.Uint64(data[24:32])
	e.ProcessStartNs = binary.LittleEndian.Uint64(data[32:40])
	e.ParentStartNs = binary.LittleEndian.Uint64(data[40:48])
	e.ThreadStartNs = binary.LittleEndian.Uint64(data[48:56])
	e.SyscallStartNs = binary.LittleEndian.Uint64(data[56:64])
	e.SyscallNr = int64(binary.LittleEndian.Uint64(data[64:72]))
	e.SyscallResult = int64(binary.LittleEndian.Uint64(data[72:80]))
	e.SyscallKind = binary.LittleEndian.Uint32(data[80:84])
	e.RawExitStatus = binary.LittleEndian.Uint32(data[84:88])
	e.Conn = binary.LittleEndian.Uint64(data[88:96])
	e.ConnEpoch = binary.LittleEndian.Uint64(data[96:104])
	e.TlsStream = binary.LittleEndian.Uint64(data[104:112])
	e.TlsCall = binary.LittleEndian.Uint64(data[112:120])
	e.TlsOffset = binary.LittleEndian.Uint32(data[120:124])
	e.Daddr = binary.LittleEndian.Uint32(data[124:128])
	e.Dport = binary.LittleEndian.Uint16(data[128:130])
	e.ExitCode = int32(binary.LittleEndian.Uint32(data[132:136]))
	copy(e.Comm[:], data[136:152])
	copy(e.Path[:], data[152:408])
	copy(e.Args[:], data[408:920])
	return e, nil
}

// There is one producer and one consumer, preserving TLS chunk and syscall
// order. ReadInto reuses the sample allocation; queued structs own their bytes.
func readSensorEvents(rd *ringbuf.Reader) (<-chan sensorbpfSensorEvent, <-chan error, func()) {
	records := make(chan sensorbpfSensorEvent, sensorQueueCapacity)
	result := make(chan error, 1)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer close(records)
		var sample ringbuf.Record
		for {
			if err := rd.ReadInto(&sample); err != nil {
				result <- err
				return
			}
			e, err := decodeSensorEvent(sample.RawSample)
			if err != nil {
				result <- err
				return
			}
			select {
			case records <- e:
			case <-stop:
				result <- ringbuf.ErrClosed
				return
			}
		}
	}()
	return records, result, func() { close(stop); _ = rd.Close(); <-done }
}
