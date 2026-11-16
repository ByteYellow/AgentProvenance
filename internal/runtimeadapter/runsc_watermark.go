package runtimeadapter

import "time"

type ProcessDrain struct {
	ObservedAt time.Time       `json:"observed_at"`
	Basis      string          `json:"basis"`
	Empty      bool            `json:"empty"`
	Remaining  []SentryProcess `json:"remaining"`
}

type RuntimeBarrier struct {
	Process SentryProcess `json:"process"`
	Marker  string        `json:"marker"`
}
