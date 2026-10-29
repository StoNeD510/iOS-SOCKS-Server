package engine

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// ringLog keeps the last N log lines for display in the app.
type ringLog struct {
	mu    sync.Mutex
	lines []string
	next  int
	full  bool
	echo  func(string)
}

func newRingLog(n int) *ringLog { return &ringLog{lines: make([]string, n)} }

func (r *ringLog) Printf(format string, args ...any) {
	line := time.Now().Format("15:04:05 ") + fmt.Sprintf(format, args...)
	r.mu.Lock()
	r.lines[r.next] = line
	r.next = (r.next + 1) % len(r.lines)
	if r.next == 0 {
		r.full = true
	}
	echo := r.echo
	r.mu.Unlock()
	if echo != nil {
		echo(line)
	}
}

func (r *ringLog) Tail() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	if r.full {
		out = append(out, r.lines[r.next:]...)
	}
	out = append(out, r.lines[:r.next]...)
	return strings.Join(out, "\n")
}

// NewLog creates a ring log holding n lines.
func NewLog(n int) *ringLog { return newRingLog(n) }

// SetEcho mirrors every line to fn (used by tests).
func (r *ringLog) SetEcho(fn func(string)) { r.mu.Lock(); r.echo = fn; r.mu.Unlock() }
