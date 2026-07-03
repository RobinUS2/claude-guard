package main

import (
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/RobinUS2/claude-guard/internal/hook"
)

// cmdWebFetchAllow is the PostToolUse hook entrypoint for WebFetch.
//
// When Claude Code completes a WebFetch — regardless of whether the user
// manually approved it or a PermissionRequest hook auto-approved it — this
// command adds the base domain to the global allow list. The next request
// to any subdomain of that base domain skips the permission dialog entirely.
//
// Wire format: reads the standard PostToolUse JSON from stdin (same shape as
// PreToolUse), writes nothing to stdout (PostToolUse hooks don't block the tool).
func cmdWebFetchAllow(_ []string) int {
	return runWebFetchAllow(os.Stdin, os.Stderr)
}

func runWebFetchAllow(in io.Reader, errOut io.Writer) int {
	req, err := hook.ReadRequest(in)
	if err != nil {
		return 0 // fail silently — never block the user
	}

	wf, err := req.WebFetch()
	if err != nil {
		return 0 // not a WebFetch call
	}

	if wf.URL == "" {
		return 0
	}

	u, err := url.Parse(wf.URL)
	if err != nil || u.Host == "" {
		return 0
	}

	host := u.Hostname()

	// Never add private/loopback IPs to the allow list.
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
			return 0
		}
	}

	domain := baseDomain(host)

	// Add both the exact hostname (e.g. www.nu.nl) AND the base domain
	// (e.g. nu.nl) because Claude Code's domain matching is exact — a rule
	// for nu.nl does NOT match www.nu.nl.
	var rulesToAdd []string
	rulesToAdd = append(rulesToAdd, "WebFetch(domain:"+domain+")")
	if host != domain {
		rulesToAdd = append(rulesToAdd, "WebFetch(domain:"+host+")")
	}

	path := settingsPathFn()
	s, err := readSettings(path)
	if err != nil {
		fmt.Fprintf(errOut, "claude-guard webfetch-allow: read settings: %v\n", err)
		return 0
	}

	existingSet := make(map[string]bool, len(s.Permissions.Allow))
	for _, r := range s.Permissions.Allow {
		existingSet[r] = true
	}

	var added []string
	newAllow := s.Permissions.Allow
	for _, rule := range rulesToAdd {
		if !existingSet[rule] {
			newAllow = append(newAllow, rule)
			added = append(added, rule)
		}
	}

	if len(added) == 0 {
		return 0 // all rules already present
	}

	if err := writeSettings(path, s, newAllow); err != nil {
		fmt.Fprintf(errOut, "claude-guard webfetch-allow: write settings: %v\n", err)
		return 0
	}

	appendWebfetchEvent(webfetchEvent{Event: "domain_learned", Domain: domain})
	return 0
}

// baseDomain returns the registrable domain (eTLD+1) for a hostname using a
// simple two-part heuristic: the last two dot-separated labels.
//
// Precondition: host must be a DNS name, not a numeric IP. Callers should
// return early for IPs (net.ParseIP(host) != nil) before calling this.
//
// This handles the vast majority of real-world TLDs (.com, .io, .dev, .nl,
// .org, .net, etc.). Multi-part country TLDs like .co.uk are a known
// limitation — they resolve to "co.uk" rather than the intended base.
// We accept this in exchange for zero external dependencies.
func baseDomain(host string) string {
	// Numeric IPs (including IPv6) are returned unchanged — splitting on "."
	// or ":" would corrupt them. The caller's IP guard should have returned
	// before we get here; this is a defensive backstop.
	if net.ParseIP(host) != nil {
		return host
	}
	// Strip port from hostnames using the last colon heuristic — valid only
	// for DNS names (IPv6 addrs are already handled above).
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}
	parts := strings.Split(host, ".")
	if len(parts) <= 2 {
		return host
	}
	return strings.Join(parts[len(parts)-2:], ".")
}
