package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/RobinUS2/claude-guard/internal/config"
	clog "github.com/RobinUS2/claude-guard/internal/log"
	"github.com/RobinUS2/claude-guard/internal/stop"
)

// stopRuleStat counts one rule's Stop hook outcomes in the window.
type stopRuleStat struct {
	Blocked    int // enforce mode: the session was sent back to work
	WouldBlock int // log mode: the rule matched and the session stopped
	Blind      int // the rule was skipped: no transcript data was available
	sessions   map[string]struct{}
}

const (
	statBlocked = iota
	statWouldBlock
	statBlind
)

// collectStopStats reads the decision log and counts, per rule, enforced
// blocks (stop_hook records that injected a message) and log-mode matches
// (stop_would_block records). No message text is read or kept.
func collectStopStats(r io.Reader, cutoff time.Time) map[string]*stopRuleStat {
	out := map[string]*stopRuleStat{}
	add := func(rule, session string, kind int) {
		st := out[rule]
		if st == nil {
			st = &stopRuleStat{sessions: map[string]struct{}{}}
			out[rule] = st
		}
		switch kind {
		case statBlocked:
			st.Blocked++
		case statWouldBlock:
			st.WouldBlock++
		case statBlind:
			st.Blind++
		}
		if session != "" {
			st.sessions[session] = struct{}{}
		}
	}

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<16), 1<<20)
	for sc.Scan() {
		var rec struct {
			Time      string `json:"time"`
			Msg       string `json:"msg"`
			SessionID string `json:"session_id"`
			Rule      string `json:"rule"`
			FiredRule string `json:"fired_rule"`
			Injected  bool   `json:"injected"`
		}
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			continue
		}
		if rec.Msg != clog.MsgStopHook && rec.Msg != clog.MsgStopWouldBlock && rec.Msg != clog.MsgStopBlind {
			continue
		}
		if ts, err := time.Parse(time.RFC3339Nano, rec.Time); err != nil || ts.Before(cutoff) {
			continue
		}
		switch rec.Msg {
		case clog.MsgStopHook:
			if rec.Injected && rec.FiredRule != "" {
				add(rec.FiredRule, rec.SessionID, statBlocked)
			}
		case clog.MsgStopWouldBlock:
			add(rec.Rule, rec.SessionID, statWouldBlock)
		case clog.MsgStopBlind:
			add(rec.Rule, rec.SessionID, statBlind)
		}
	}
	return out
}

// cmdStopStats prints, per Stop rule, how often it blocked (enforce) or would
// have blocked (log) and in how many distinct sessions.
//
//	claude-guard stop-stats [--since 7d] [--path decisions.jsonl]
func cmdStopStats(args []string, w io.Writer) int {
	fs := flag.NewFlagSet("stop-stats", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var sinceStr, pathOverride string
	fs.StringVar(&sinceStr, "since", "7d", "only consider log entries from the last N (e.g. 24h, 7d)")
	fs.StringVar(&pathOverride, "path", "", "override the decisions log path")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	since := parseSince(sinceStr, 7*24*time.Hour)

	cfg := config.Load("").Config
	path := pathOverride
	if path == "" {
		logDir := cfg.Log.Dir
		if logDir == "" {
			logDir = config.DefaultLogDir()
		}
		path = clog.DefaultPaths(logDir).Decisions
	}
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "stop-stats: cannot read %s: %v\n", path, err)
		return 1
	}
	defer f.Close()

	stats := collectStopStats(f, time.Now().Add(-since))
	names := make([]string, 0, len(stats))
	for n := range stats {
		names = append(names, n)
	}
	sort.Strings(names)

	fmt.Fprintf(w, "stop rule stats (last %s)\n\n", sinceStr)
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "RULE\tMODE\tBLOCKED\tWOULD BLOCK\tBLIND\tSESSIONS")
	for _, n := range names {
		st := stats[n]
		fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%d\t%d\n", n, stop.RuleMode(n, cfg.Stop.Modes), st.Blocked, st.WouldBlock, st.Blind, len(st.sessions))
	}
	tw.Flush()
	if len(names) == 0 {
		fmt.Fprintln(w, "no Stop rule matches in this window")
	}
	return 0
}
