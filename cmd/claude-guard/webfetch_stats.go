package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// webfetchEvent is one line in ~/.cache/claude-guard/webfetch-events.log.
// The log is append-only NDJSON — no locking needed (appends < 512B are
// atomic on macOS/Linux for O_APPEND).
type webfetchEvent struct {
	Time     string `json:"t"`
	Event    string `json:"event"`              // "inspected" | "domain_learned"
	Decision string `json:"decision,omitempty"` // "allow" | "ask"
	Domain   string `json:"domain,omitempty"`
}

func webfetchLogPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".cache", "claude-guard", "webfetch-events.log")
}

// appendWebfetchEvent writes a single event line. Fails silently — never
// blocks the hook caller.
func appendWebfetchEvent(ev webfetchEvent) {
	ev.Time = time.Now().UTC().Format(time.RFC3339)
	line, err := json.Marshal(ev)
	if err != nil {
		return
	}
	line = append(line, '\n')

	f, err := os.OpenFile(webfetchLogPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(line)
}

// cmdWebFetchStats prints aggregated WebFetch hook counters.
func cmdWebFetchStats(args []string) int {
	todayOnly := len(args) > 0 && args[0] == "--today"
	today := time.Now().UTC().Format("2006-01-02")

	f, err := os.Open(webfetchLogPath())
	if err != nil {
		fmt.Println("No WebFetch stats yet — hook hasn't fired.")
		return 0
	}
	defer f.Close()

	type counts struct {
		asked, autoAllowed, userPrompted, domainsLearned int
	}
	all := counts{}
	day := counts{}

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var ev webfetchEvent
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			continue
		}
		isToday := strings.HasPrefix(ev.Time, today)

		switch ev.Event {
		case "inspected":
			all.asked++
			if ev.Decision == "allow" {
				all.autoAllowed++
			} else {
				all.userPrompted++
			}
			if isToday {
				day.asked++
				if ev.Decision == "allow" {
					day.autoAllowed++
				} else {
					day.userPrompted++
				}
			}
		case "domain_learned":
			all.domainsLearned++
			if isToday {
				day.domainsLearned++
			}
		}
	}

	pct := func(n, total int) string {
		if total == 0 || n == 0 {
			return ""
		}
		return fmt.Sprintf("  (%d%%)", n*100/total)
	}

	printCounts := func(label string, c counts) {
		fmt.Printf("%s\n", label)
		if c.asked == 0 && c.domainsLearned == 0 {
			fmt.Println("  (no data)")
			return
		}
		fmt.Printf("  Inspected:       %4d\n", c.asked)
		fmt.Printf("  Auto-allowed:    %4d%s\n", c.autoAllowed, pct(c.autoAllowed, c.asked))
		fmt.Printf("  User prompted:   %4d%s\n", c.userPrompted, pct(c.userPrompted, c.asked))
		fmt.Printf("  Domains learned: %4d\n", c.domainsLearned)
	}

	if todayOnly {
		printCounts("WebFetch stats — today ("+today+"):", day)
	} else {
		printCounts("WebFetch stats — today ("+today+"):", day)
		fmt.Println()
		printCounts("WebFetch stats — all time:", all)
	}

	return 0
}
