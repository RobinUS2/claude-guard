package shellparse

import "mvdan.cc/sh/v3/syntax"

// ForLoopExpansion is the result of a safe-to-evaluate for-loop
// expansion. Callers use it to run each synthesized body call through
// the existing single-call rule machinery (AnchoredCommand,
// posix-readonly, etc.) as if the user had typed out every iteration.
//
// Shape restrictions enforced by ExpandForLoop:
//   - Exactly one top-level statement.
//   - That statement is `for <var> in <literal1> <literal2> ...; do <body>; done`
//     — a WordIter form, NOT the C-style `for ((i=0;i<n;i++))`.
//   - All iterator items are statically resolvable literals (no $(...),
//     no unresolved parameter expansion, no globs with side effects).
//   - No background, no top-level redirections.
//   - No shell features that change semantics: subshell, process
//     substitution, command substitution, background, pipes (HasPipe
//     within the body would be allowed in a future extension; for v1
//     we reject to keep the surface small).
//   - Each body Stmt is a plain CallExpr (not a Block/If/Case/etc).
//   - Each body Call's program slot is a literal (no `$CMD` invocation).
//   - The ONLY permissible unresolved expansion in body args is a bare
//     reference to the loop iterator variable, either `$name` or
//     `${name}`. Mixed shapes like `"$name-suffix"` are accepted —
//     substitution happens at the Word level and a DblQuoted wrapper
//     is fine.
//
// When all restrictions hold, ExpandForLoop returns one resolved Call
// per (iteration × body statement), with HasUnresolved=false and the
// iterator substituted into each relevant Word.
type ForLoopExpansion struct {
	IteratorName string
	Items        []string
	Calls        []Call
}

// ExpandForLoop inspects the parsed command for a safe top-level
// for-loop and, when the shape qualifies, returns an expansion plus
// true. Callers use the expansion's Calls to run each synthesized
// iteration body through single-call rules.
//
// maxIterations caps Items; pass 0 for no cap. A value over the cap
// returns (nil, false) so rules can distinguish "unsafe" from "simply
// too large" without peeking.
//
// Returns (nil, false) for any shape that doesn't match the
// restrictions documented on ForLoopExpansion. Never panics.
func ExpandForLoop(p *Parsed, maxIterations int) (*ForLoopExpansion, bool) {
	if p == nil || p.File == nil {
		return nil, false
	}
	// Top-level shape: one statement, no background/redirs.
	if len(p.File.Stmts) != 1 {
		return nil, false
	}
	stmt := p.File.Stmts[0]
	if stmt == nil || stmt.Background || len(stmt.Redirs) > 0 {
		return nil, false
	}
	// Reject shell features that make expansion-then-rule-check unsafe.
	// HasMultiStmt is impossible with a single top-level Stmt, but
	// HasBinaryOp might be true if the loop body has && or ; — we
	// require each body Stmt to be a simple CallExpr instead, so any
	// binary op in the body means the body isn't a plain call and we
	// reject below.
	f := p.Features
	if f.HasSubshell || f.HasCmdSub || f.HasProcSub || f.HasBackground {
		return nil, false
	}
	if f.HasRedirect && !f.HasFdOnlyRedirects {
		return nil, false
	}
	if f.HasPipe {
		return nil, false
	}
	fc, ok := stmt.Cmd.(*syntax.ForClause)
	if !ok {
		return nil, false
	}
	wi, ok := fc.Loop.(*syntax.WordIter)
	if !ok || wi.Name == nil {
		return nil, false
	}
	iterVar := wi.Name.Value
	if iterVar == "" {
		return nil, false
	}
	if len(wi.Items) == 0 || len(fc.Do) == 0 {
		return nil, false
	}
	if maxIterations > 0 && len(wi.Items) > maxIterations {
		return nil, false
	}
	items := make([]string, 0, len(wi.Items))
	for _, w := range wi.Items {
		lit, ok := resolveWord(w)
		if !ok {
			return nil, false
		}
		items = append(items, lit)
	}
	// Body validation: every Stmt must be a simple CallExpr, no
	// per-stmt background/redirs, and every program slot must be
	// literal.
	bodyCalls := make([]*syntax.CallExpr, 0, len(fc.Do))
	for _, bstmt := range fc.Do {
		if bstmt == nil || bstmt.Background {
			return nil, false
		}
		// fd-only redirects (2>&1) are OK; file redirects change
		// semantics and are rejected by the file-level redirect check
		// above when HasFdOnlyRedirects is false. Per-stmt we don't
		// need to re-check.
		ce, ok := bstmt.Cmd.(*syntax.CallExpr)
		if !ok {
			return nil, false
		}
		if len(ce.Args) == 0 {
			return nil, false
		}
		prog, progOK := resolveWord(ce.Args[0])
		if !progOK || prog == "" {
			return nil, false
		}
		bodyCalls = append(bodyCalls, ce)
	}
	// Synthesize one Call per (iteration, body-stmt) with the iterator
	// substituted in. A body arg is only acceptable if every unresolved
	// part is a ParamExp naming iterVar (possibly inside a DblQuoted
	// wrapper). Everything else (random $OTHER, $(...), arith) fails.
	out := make([]Call, 0, len(items)*len(bodyCalls))
	for _, v := range items {
		for _, ce := range bodyCalls {
			call, ok := synthesizeCall(ce, iterVar, v)
			if !ok {
				return nil, false
			}
			out = append(out, call)
		}
	}
	return &ForLoopExpansion{
		IteratorName: iterVar,
		Items:        items,
		Calls:        out,
	}, true
}

// synthesizeCall builds a shellparse.Call from a body CallExpr with
// iterVar expansion substituted. Returns (_, false) if any argument
// contains an unresolved expansion other than a reference to iterVar,
// or if the program slot is unresolved.
func synthesizeCall(c *syntax.CallExpr, iterVar, iterVal string) (Call, bool) {
	call := Call{Expr: c, Nesting: NestTopLevel}
	prog, ok := resolveWord(c.Args[0])
	if !ok || prog == "" {
		return Call{}, false
	}
	call.Program = prog
	for _, w := range c.Args[1:] {
		lit, ok := resolveWordSubstitutingIter(w, iterVar, iterVal)
		if !ok {
			return Call{}, false
		}
		call.Args = append(call.Args, lit)
		if len(lit) > 0 && lit[0] == '-' && lit != "-" {
			call.Flags = append(call.Flags, lit)
		} else {
			call.Positional = append(call.Positional, lit)
		}
	}
	return call, true
}

// resolveWordSubstitutingIter flattens a Word to a literal where every
// ParamExp naming iterVar expands to iterVal. All other unresolvable
// expansions (CmdSubst, ArithmExp, a different ParamExp) cause false.
//
// Supports:
//   - bare `$name` (ParamExp with Short=true, no modifiers)
//   - `${name}` (ParamExp with Short=false, no modifiers)
//   - either form appearing inside a DblQuoted wrapper (flat join)
func resolveWordSubstitutingIter(w *syntax.Word, iterVar, iterVal string) (string, bool) {
	if w == nil {
		return "", true
	}
	var b []byte
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			b = append(b, p.Value...)
		case *syntax.SglQuoted:
			b = append(b, p.Value...)
		case *syntax.ParamExp:
			if !isSimpleParamRef(p, iterVar) {
				return "", false
			}
			b = append(b, iterVal...)
		case *syntax.DblQuoted:
			s, ok := joinDblQuoted(p, iterVar, iterVal)
			if !ok {
				return "", false
			}
			b = append(b, s...)
		default:
			return "", false
		}
	}
	return string(b), true
}

// joinDblQuoted concatenates the parts of a double-quoted Word,
// resolving ParamExp refs to iterVar. Matches the DblQuoted handling
// in resolveWord but adds iterator substitution.
func joinDblQuoted(q *syntax.DblQuoted, iterVar, iterVal string) (string, bool) {
	var b []byte
	for _, inner := range q.Parts {
		switch ip := inner.(type) {
		case *syntax.Lit:
			b = append(b, ip.Value...)
		case *syntax.ParamExp:
			if !isSimpleParamRef(ip, iterVar) {
				return "", false
			}
			b = append(b, iterVal...)
		default:
			return "", false
		}
	}
	return string(b), true
}

// isSimpleParamRef returns true when pe is a bare reference to the
// named variable, with no modifiers (length, slicing, default,
// substring, indirection, etc.). Those modifiers can mutate the
// runtime value in ways LoopReadonly can't safely model, so we bail.
func isSimpleParamRef(pe *syntax.ParamExp, name string) bool {
	if pe == nil || pe.Param == nil {
		return false
	}
	if pe.Param.Value != name {
		return false
	}
	if pe.Excl || pe.Length || pe.Width || pe.IsSet {
		return false
	}
	if pe.Index != nil || pe.Slice != nil || pe.Repl != nil || pe.Exp != nil {
		return false
	}
	if len(pe.Modifiers) > 0 || pe.NestedParam != nil || pe.Flags != nil {
		return false
	}
	if pe.Names != 0 {
		return false
	}
	return true
}
