package main

// Node-local dynamic-residual admission gate.
//
// This is the part of kubelet node admission that genuinely must run at
// activation time — capacity drift + node pressure — implemented by reading
// kernel state DIRECTLY (/proc/meminfo, /proc/pressure/memory), never via the
// kubelet. The static admission checks (OS/affinity/sysctl/...) are pre-validated
// at registration when the phantom is scheduled; only this residual remains.
//
// Two layers, both must pass:
//   L1 (accounting): an in-memory committed-memory counter, atomically checked
//      against a phantom budget. Prevents OUR pool from over-committing the node
//      under concurrent claims (the TOCTOU-safe replacement for "flip an
//      annotation when calc<actual").
//   L2 (drift): a live read of MemAvailable + PSI some-avg10. Catches memory the
//      counter cannot see (system daemons, static/mirror pods, kernel slab) — the
//      genuine residual the scheduler could not have known.
//
// The committed counter is the hot-path source of truth; any
// phantomk8s.io/activated annotation is an async durable mirror, not this.

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
)

type AdmissionGate struct {
	mu          sync.Mutex
	committedKB int64 // sum of activation deltas currently held

	budgetKB      int64   // L1 ceiling: max phantom memory commit on this node
	memAvailMinKB int64   // L2: reject if MemAvailable below this
	psiSomeMax    float64 // L2: reject if /proc/pressure/memory some avg10 above this (0=off)
	parkedCostKB  int64   // idle parked cost subtracted from limit → activation delta
}

type GateConfig struct {
	BudgetMB      int64
	MemAvailMinMB int64
	PSISomeMax    float64
	ParkedCostMB  int64
}

func NewAdmissionGate(cfg GateConfig) *AdmissionGate {
	budgetKB := cfg.BudgetMB * 1024
	if budgetKB <= 0 {
		// Default: half of MemTotal reserved for phantoms.
		if mt := readMeminfoKB("MemTotal"); mt > 0 {
			budgetKB = mt / 2
		}
	}
	parked := cfg.ParkedCostMB * 1024
	if parked < 0 {
		parked = 0
	}
	return &AdmissionGate{
		budgetKB:      budgetKB,
		memAvailMinKB: cfg.MemAvailMinMB * 1024,
		psiSomeMax:    cfg.PSISomeMax,
		parkedCostKB:  parked,
	}
}

// Admit runs L1 (atomic accounting) then L2 (live drift). limitKB is the
// phantom's memory.max in KB (0 = no declared limit → counts parkedCost worth,
// i.e. delta 0). Returns (deltaKB, ok, reason). On ok, the gate has RESERVED
// deltaKB — the caller MUST Release(deltaKB) on teardown or launch failure.
func (g *AdmissionGate) Admit(limitKB int64) (int64, bool, string) {
	delta := limitKB - g.parkedCostKB
	if delta < 0 {
		delta = 0
	}

	// L1: atomic committed-counter check + reserve.
	g.mu.Lock()
	if g.committedKB+delta > g.budgetKB {
		over := (g.committedKB + delta - g.budgetKB) / 1024
		committed := g.committedKB / 1024
		budget := g.budgetKB / 1024
		g.mu.Unlock()
		return 0, false, fmt.Sprintf("phantom budget exceeded by %dMB (committed=%dMB budget=%dMB)", over, committed, budget)
	}
	g.committedKB += delta
	g.mu.Unlock()

	// L2: live drift — node pressure the counter can't see. Roll back L1 on fail.
	if reason, ok := g.checkDrift(); !ok {
		g.Release(delta)
		return 0, false, reason
	}
	return delta, true, ""
}

// releaseIf is a nil-safe Release: a no-op when the gate is disabled (nil) or
// the delta is zero. Safe to call on a nil *AdmissionGate.
func (g *AdmissionGate) releaseIf(deltaKB int64) {
	if g == nil || deltaKB <= 0 {
		return
	}
	g.Release(deltaKB)
}

// Release returns a previously-reserved delta to the budget. Idempotent-safe
// against negative drift (clamps at 0).
func (g *AdmissionGate) Release(deltaKB int64) {
	if deltaKB <= 0 {
		return
	}
	g.mu.Lock()
	g.committedKB -= deltaKB
	if g.committedKB < 0 {
		g.committedKB = 0
	}
	g.mu.Unlock()
}

func (g *AdmissionGate) checkDrift() (string, bool) {
	if g.memAvailMinKB > 0 {
		if avail := readMeminfoKB("MemAvailable"); avail > 0 && avail < g.memAvailMinKB {
			return fmt.Sprintf("MemAvailable %dMB below min %dMB", avail/1024, g.memAvailMinKB/1024), false
		}
	}
	if g.psiSomeMax > 0 {
		if some := readPSISomeAvg10(); some > g.psiSomeMax {
			return fmt.Sprintf("memory PSI some avg10 %.1f over max %.1f", some, g.psiSomeMax), false
		}
	}
	return "", true
}

func (g *AdmissionGate) Stats() (committedMB, budgetMB int64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.committedKB / 1024, g.budgetKB / 1024
}

// readMeminfoKB parses /proc/meminfo for a key like "MemAvailable" → value in kB.
func readMeminfoKB(key string) int64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	prefix := key + ":"
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, prefix) {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				v, _ := strconv.ParseInt(fields[1], 10, 64)
				return v // already kB in /proc/meminfo
			}
		}
	}
	return 0
}

// readPSISomeAvg10 parses /proc/pressure/memory "some avg10=X.XX ..." → X.XX.
// Returns 0 if PSI is unavailable (older kernels / not mounted).
func readPSISomeAvg10() float64 {
	f, err := os.Open("/proc/pressure/memory")
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "some ") {
			for _, tok := range strings.Fields(line) {
				if strings.HasPrefix(tok, "avg10=") {
					v, _ := strconv.ParseFloat(strings.TrimPrefix(tok, "avg10="), 64)
					return v
				}
			}
		}
	}
	return 0
}

// parseQuantityKB parses a K8s resource quantity string ("256Mi", "1Gi", "512M",
// "1073741824") into kB. Returns 0 on empty/parse error. Two-char binary
// suffixes are checked before single-char decimal ones.
func parseQuantityKB(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	type suf struct {
		s string
		m int64
	}
	for _, sf := range []suf{
		{"Ki", 1024}, {"Mi", 1024 * 1024}, {"Gi", 1024 * 1024 * 1024}, {"Ti", 1024 * 1024 * 1024 * 1024},
		{"K", 1000}, {"M", 1000 * 1000}, {"G", 1000 * 1000 * 1000}, {"T", 1000 * 1000 * 1000 * 1000},
		{"k", 1000},
	} {
		if strings.HasSuffix(s, sf.s) {
			num := strings.TrimSpace(strings.TrimSuffix(s, sf.s))
			v, err := strconv.ParseFloat(num, 64)
			if err != nil {
				return 0
			}
			return int64(v*float64(sf.m)) / 1024
		}
	}
	// plain bytes
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	return int64(v) / 1024
}
