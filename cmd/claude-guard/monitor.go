package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/RobinUS2/claude-guard/internal/config"
	clog "github.com/RobinUS2/claude-guard/internal/log"
)

// cmdMonitor live-tails the decisions log and pretty-prints each record as
// it arrives. Useful during shadow mode and while debugging rule changes.
//
//	claude-guard monitor              # follow decisions.jsonl forever
//	claude-guard monitor --since 100  # print last 100 entries then follow
//	claude-guard monitor --no-follow  # print then exit (like `cat`)
//	claude-guard monitor --verdict deny  # only show blocked decisions
//	claude-guard monitor --tier instant_block
//	claude-guard monitor --json          # raw JSON lines (for piping to jq)
func cmdMonitor(args []string) int {
	fs := flag.NewFlagSet("monitor", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var (
		follow      bool
		since       int
		verdict     string
		tier        string
		rawJSON     bool
		pathOverride string
	)
	fs.BoolVar(&follow, "follow", true, "keep following the log after printing existing entries")
	fs.BoolVar(&follow, "f", true, "alias for --follow")
	followOff := fs.Bool("no-follow", false, "stop after printing existing entries (inverse of --follow)")
	fs.IntVar(&since, "since", 0, "print last N entries before following (0 = all)")
	fs.StringVar(&verdict, "verdict", "", "filter by verdict (allow, deny, continue)")
	fs.StringVar(&tier, "tier", "", "filter by tier (instant_block, instant_allow, default, parse_error)")
	fs.BoolVar(&rawJSON, "json", false, "print raw JSON lines instead of pretty-printed output")
	fs.StringVar(&pathOverride, "path", "", "log file path override (default: from config)")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *followOff {
		follow = false
	}

	path := pathOverride
	if path == "" {
		result := config.Load("")
		path = result.Config.Log.Path
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "monitor: log file does not exist yet: %s\n", path)
		fmt.Fprintln(os.Stderr, "monitor: waiting for first entry…")
		for {
			if _, err := os.Stat(path); err == nil {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
	}

	filter := func(rec clog.Record) bool {
		if verdict != "" && rec.Verdict != verdict {
			return false
		}
		if tier != "" && rec.Tier != tier {
			return false
		}
		return true
	}

	// Open the file; if --since > 0, seek to the last N lines.
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "monitor: open log: %v\n", err)
		return 1
	}
	defer f.Close()

	if since > 0 {
		if err := seekToLastNLines(f, since); err != nil {
			fmt.Fprintf(os.Stderr, "monitor: seek: %v\n", err)
			// fall back to full read
			_, _ = f.Seek(0, io.SeekStart)
		}
	}

	reader := bufio.NewReaderSize(f, 1<<16)
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			printLine(line, filter, rawJSON)
		}
		if err != nil {
			if err != io.EOF {
				fmt.Fprintf(os.Stderr, "monitor: read: %v\n", err)
				return 1
			}
			if !follow {
				return 0
			}
			// Check for rotation: if the file has shrunk or the inode has
			// changed, reopen. Otherwise sleep briefly and retry.
			if rotated, err := wasRotated(f, path); err == nil && rotated {
				nf, err := os.Open(path)
				if err == nil {
					_ = f.Close()
					f = nf
					reader.Reset(f)
					continue
				}
			}
			time.Sleep(250 * time.Millisecond)
			continue
		}
	}
}

func printLine(line []byte, filter func(clog.Record) bool, raw bool) {
	line = trimNewline(line)
	if len(line) == 0 {
		return
	}
	var rec clog.Record
	if err := json.Unmarshal(line, &rec); err != nil {
		// Not our schema — print raw.
		fmt.Println(string(line))
		return
	}
	if !filter(rec) {
		return
	}
	if raw {
		os.Stdout.Write(line)
		os.Stdout.Write([]byte{'\n'})
		return
	}
	prettyPrint(rec)
}

func prettyPrint(rec clog.Record) {
	ts := rec.Time.Local().Format("15:04:05")
	verdictMark := "·"
	switch rec.Verdict {
	case "allow":
		verdictMark = "✓"
	case "deny":
		verdictMark = "✗"
	case "continue":
		verdictMark = "?"
	}

	cmd := rec.Command
	if len(cmd) > 100 {
		cmd = cmd[:97] + "..."
	}

	tier := rec.Tier
	if rec.Rule != "" {
		tier = fmt.Sprintf("%s/%s", rec.Tier, rec.Rule)
	}

	fmt.Printf("%s %s [%-28s] %s\n", ts, verdictMark, tier, cmd)

	if rec.Shadow != nil {
		if rec.Shadow.Tier1Block != "" {
			fmt.Printf("         shadow-tier1-block: %s\n", rec.Shadow.Tier1Block)
		}
		if rec.Shadow.Tier2Allow != "" {
			fmt.Printf("         shadow-tier2-allow: %s\n", rec.Shadow.Tier2Allow)
		}
		if rec.Shadow.Tier4LLM != "" {
			fmt.Printf("         shadow-tier4-llm:   %s\n", rec.Shadow.Tier4LLM)
		}
	}
	if rec.Reason != "" && rec.Verdict == "deny" {
		fmt.Printf("         reason: %s\n", rec.Reason)
	}
	if rec.Description != "" {
		fmt.Printf("         desc:   %s\n", rec.Description)
	}
}

func trimNewline(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

// seekToLastNLines positions f at the start of the N-th-to-last line.
// It reads backwards from EOF in 4KB chunks counting newlines.
func seekToLastNLines(f *os.File, n int) error {
	const chunkSize = 4096
	stat, err := f.Stat()
	if err != nil {
		return err
	}
	size := stat.Size()
	if size == 0 {
		return nil
	}

	buf := make([]byte, chunkSize)
	pos := size
	lines := 0
	for pos > 0 {
		read := int64(chunkSize)
		if pos < read {
			read = pos
		}
		pos -= read
		if _, err := f.ReadAt(buf[:read], pos); err != nil {
			return err
		}
		for i := int(read) - 1; i >= 0; i-- {
			if buf[i] == '\n' {
				lines++
				if lines > n {
					_, err := f.Seek(pos+int64(i)+1, io.SeekStart)
					return err
				}
			}
		}
	}
	_, err = f.Seek(0, io.SeekStart)
	return err
}

// wasRotated checks whether the file at path is the same as f, using inode
// comparison on Unix. If the inode changed, the file was rotated.
func wasRotated(f *os.File, path string) (bool, error) {
	stA, err := f.Stat()
	if err != nil {
		return false, err
	}
	stB, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return !os.SameFile(stA, stB), nil
}
