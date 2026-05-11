// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 CEMAXECUTER LLC
//
// wardrive/sniffer_proc.go: spawn meshtastic-sniffer as a child
// process and manage its lifecycle.
//
// Reuses the existing C sniffer for radio control and bit-level DSP
// rather than re-implementing those in Go. Communication with the
// child is over its existing ZMQ PUB socket (zmq_sub.go subscribes).
// Stderr is forwarded so the operator sees the sniffer's "[stats]"
// heartbeats and any warnings.

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

// SnifferProc owns a child `meshtastic-sniffer` process. Start()
// launches it; the process runs until ctx is cancelled or the
// child exits. On unexpected exit the parent logs and exits with
// status 1 (wardrive's invariant: no radio == no useful work).
type SnifferProc struct {
	BinaryPath  string   // path to the meshtastic-sniffer binary
	Args        []string // forwarded flags (--hackrf, --keys, ...)
	ZMQEndpoint string   // tcp://127.0.0.1:7008 by default; appended to Args
	StderrSink  io.Writer

	mu  sync.Mutex
	cmd *exec.Cmd
}

// FindSnifferBinary looks for meshtastic-sniffer in the usual places.
// Order:
//
//	1. WARDRIVE_SNIFFER env var (operator override)
//	2. ./meshtastic-sniffer in CWD
//	3. ../build/meshtastic-sniffer (developer working tree)
//	4. /usr/local/bin/meshtastic-sniffer
//	5. PATH lookup
//
// Returns the resolved absolute path or an error if no candidate
// is executable.
func FindSnifferBinary() (string, error) {
	if p := os.Getenv("WARDRIVE_SNIFFER"); p != "" {
		if abs, err := filepath.Abs(p); err == nil {
			if _, err := os.Stat(abs); err == nil {
				return abs, nil
			}
		}
	}
	candidates := []string{
		"./meshtastic-sniffer",
		"../build/meshtastic-sniffer",
		"../meshtastic-sniffer",
		"/usr/local/bin/meshtastic-sniffer",
	}
	for _, p := range candidates {
		abs, err := filepath.Abs(p)
		if err != nil {
			continue
		}
		if fi, err := os.Stat(abs); err == nil && !fi.IsDir() {
			if fi.Mode()&0111 != 0 {
				return abs, nil
			}
		}
	}
	if p, err := exec.LookPath("meshtastic-sniffer"); err == nil {
		return p, nil
	}
	return "", errors.New("meshtastic-sniffer not found in PATH; set WARDRIVE_SNIFFER=/path")
}

// Start launches the sniffer subprocess. Blocking call: returns when
// the child exits or ctx is cancelled. Forwards stderr to
// p.StderrSink (or os.Stderr if nil). Returns the child's exit error.
func (p *SnifferProc) Start(ctx context.Context) error {
	if p.BinaryPath == "" {
		return errors.New("BinaryPath empty")
	}
	if p.ZMQEndpoint == "" {
		p.ZMQEndpoint = "tcp://127.0.0.1:7008"
	}
	args := append([]string{}, p.Args...)
	if !hasFlag(args, "--zmq=") && !hasFlag(args, "--zmq") {
		args = append(args, "--zmq="+p.ZMQEndpoint)
	}

	cmd := exec.CommandContext(ctx, p.BinaryPath, args...)
	cmd.Stdout = io.Discard // sniffer stdout is the JSON firehose; we use ZMQ instead
	if p.StderrSink != nil {
		cmd.Stderr = p.StderrSink
	} else {
		cmd.Stderr = os.Stderr
	}
	log.Printf("sniffer: launching %s %v", p.BinaryPath, args)
	p.mu.Lock()
	p.cmd = cmd
	p.mu.Unlock()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("sniffer start: %w", err)
	}
	pid := cmd.Process.Pid
	log.Printf("sniffer: pid=%d", pid)

	// Wait in a goroutine so we can surface ctx cancellation as a
	// clean shutdown (SIGINT to the child).
	doneCh := make(chan error, 1)
	go func() {
		doneCh <- cmd.Wait()
	}()
	select {
	case <-ctx.Done():
		// Parent context cancelled. exec.CommandContext already SIGKILLs
		// on Cancel, but we want SIGINT so the sniffer can flush its
		// pcap / archive / stats.
		_ = cmd.Process.Signal(os.Interrupt)
		select {
		case err := <-doneCh:
			return err
		case <-time.After(3 * time.Second):
			_ = cmd.Process.Kill()
			return <-doneCh
		}
	case err := <-doneCh:
		return err
	}
}

// hasFlag returns whether args contains a flag matching `prefix`
// (either "--zmq=..." or "--zmq" form).
func hasFlag(args []string, prefix string) bool {
	for _, a := range args {
		if a == prefix || (len(a) > len(prefix) && a[:len(prefix)] == prefix) {
			return true
		}
	}
	return false
}
