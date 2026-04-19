package shellparse

import "mvdan.cc/sh/v3/syntax"

// OnlyStderrMergeRedirect reports whether every redirect in the parsed
// script is exactly `2>&1` (stderr→stdout merge) and nothing else. Used
// by tier-2 allow rules that want to accept the common shell idiom
// without opening the door to file redirects.
//
// Returns false when there are no redirects at all; callers typically
// guard with Features.HasRedirect first.
//
// The check is structural — walks the AST for *syntax.Redirect nodes
// and verifies each one matches the `N=2, Op=>&, Word=1` shape. Does
// NOT do string matching: `echo "2>&1"` has no redirect and therefore
// returns false; `cmd > /tmp/out 2>&1` has a file redirect and returns
// false.
func (p *Parsed) OnlyStderrMergeRedirect() bool {
	if !p.Features.HasRedirect || p.File == nil {
		return false
	}
	ok := true
	sawRedir := false
	syntax.Walk(p.File, func(n syntax.Node) bool {
		if !ok {
			return false
		}
		r, isRedir := n.(*syntax.Redirect)
		if !isRedir {
			return true
		}
		sawRedir = true
		// Must be `>&` operator.
		if r.Op != syntax.DplOut {
			ok = false
			return false
		}
		// Must be explicitly `2>&...` (N == "2"). mvdan sets r.N for
		// numbered fd redirects; implicit `>&1` (fd 1) would have N==nil.
		if r.N == nil || r.N.Value != "2" {
			ok = false
			return false
		}
		// No heredoc body on a dup.
		if r.Hdoc != nil {
			ok = false
			return false
		}
		// Word must be the literal "1".
		if r.Word == nil {
			ok = false
			return false
		}
		lit, wordOK := resolveWord(r.Word)
		if !wordOK || lit != "1" {
			ok = false
			return false
		}
		return true
	})
	return ok && sawRedir
}
