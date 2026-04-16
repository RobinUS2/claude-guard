// Package shellparse wraps mvdan.cc/sh/v3/syntax to extract the structured
// features rule matchers need: top-level command calls, pipelines, redirects,
// subshells, command substitution, process substitution, and unresolved
// expansions.
//
// The goal is defensive correctness, not full shell emulation. When a word
// contains a variable or command-substitution that we cannot statically
// resolve, we mark it as HasUnresolved and leave the decision to higher tiers
// (LLM classifier or user prompt). This is conservative: unresolved commands
// are never auto-approved by AST-based allow rules, but also cannot be matched
// against literal-string deny rules, so they fall through. That is the correct
// behavior — when in doubt, prompt the human.
package shellparse

import (
	"errors"
	"fmt"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Parsed is the result of parsing a single shell command string.
type Parsed struct {
	// Raw is the original command string as received.
	Raw string

	// File is the underlying syntax.File. Matchers that need finer detail
	// (e.g. path argument resolution under specific syntactic positions)
	// can walk this directly.
	File *syntax.File

	// TopLevelCalls is a flat list of every command invocation in the script,
	// in the order they appear in the AST. Calls inside subshells, command
	// substitution, and process substitution are included. This is the
	// primary list matchers iterate over.
	//
	// Rule matchers that need to distinguish "top-level vs nested" should
	// use the Nesting field on each Call.
	Calls []Call

	// Pipelines groups calls that are joined by `|` into ordered lists.
	// Each inner slice is one pipeline, with calls in left-to-right order.
	// A bare command (no pipe) shows up as a single-element pipeline.
	// Only top-level pipelines are listed; pipelines nested inside subshells
	// or command substitution are not (matchers that care should walk File).
	Pipelines [][]Call

	// Features is a rolled-up snapshot of what constructs the script uses.
	Features Features
}

// Features is a set of boolean flags describing the top-level script structure.
type Features struct {
	HasRedirect   bool // any >, >>, <, <&, >&, <<, <<<
	HasPipe       bool // any |
	HasSubshell   bool // (...) group or explicit subshell
	HasCmdSub     bool // $(...) or `...`
	HasProcSub    bool // <(...) or >(...)
	HasBackground bool // command ending in &
	HasBinaryOp   bool // &&, ||, ; between multiple statements
	HasMultiStmt  bool // more than one top-level statement
}

// Nesting describes where a call appears in the AST.
type Nesting int

const (
	// NestTopLevel is a call that appears directly in a top-level statement
	// (possibly inside a pipeline).
	NestTopLevel Nesting = iota
	// NestSubshell is a call inside a subshell or group command.
	NestSubshell
	// NestCmdSub is a call inside $(...) or `...`.
	NestCmdSub
	// NestProcSub is a call inside <(...) or >(...).
	NestProcSub
)

// Call describes one command invocation.
type Call struct {
	// Program is the best-effort literal program name. Empty if the program
	// slot contains a variable, command substitution, or other unresolvable
	// expansion.
	Program string

	// Args are the best-effort literal arguments. Index 0 is the first arg
	// after the program (not the program itself). Unresolvable args become
	// empty strings, so len(Args) == len(RawArgs).
	Args []string

	// Flags are args that start with '-' or '--'.
	Flags []string

	// Positional are args that do not start with '-'.
	Positional []string

	// HasUnresolved is true if Program or any Arg could not be statically
	// resolved. Conservative rule: a call with HasUnresolved=true may not
	// be auto-allowed via an anchored allow rule.
	HasUnresolved bool

	// Nesting tells where in the AST the call appeared.
	Nesting Nesting

	// Expr is the underlying syntax node. Matchers that need finer detail
	// (e.g. redirection targets of this specific call) can inspect it.
	Expr *syntax.CallExpr
}

// HasEnvVarArg returns true when any of this call's arguments (NOT the
// program slot) expands a shell variable whose name is in `names`.
// Examples: for `rm -rf "$HOME"`, HasEnvVarArg("HOME") returns true.
//
// Used by BlockedCommand to catch shapes like `rm -rf $HOME` or
// `rm -rf "$PWD"` where resolveWord returns an empty string (because
// the expansion is unresolvable at parse time), causing the positional
// slot to be empty and bypassing the TargetPaths check.
//
// Inspects ParamExp directly (both bare `$HOME` and inside
// DblQuoted `"$HOME"` or `"${HOME}"` shapes). Does NOT follow
// CmdSubst, ArithmExp, or ExtGlob.
func (c *Call) HasEnvVarArg(names ...string) bool {
	if c.Expr == nil || len(c.Expr.Args) < 2 {
		return false
	}
	nameSet := make(map[string]struct{}, len(names))
	for _, n := range names {
		nameSet[n] = struct{}{}
	}
	// Skip index 0 (program slot); scan arg words only.
	for _, arg := range c.Expr.Args[1:] {
		if arg == nil {
			continue
		}
		for _, part := range arg.Parts {
			if wordPartHasParam(part, nameSet) {
				return true
			}
		}
	}
	return false
}

func wordPartHasParam(part syntax.WordPart, nameSet map[string]struct{}) bool {
	switch p := part.(type) {
	case *syntax.ParamExp:
		if p.Param != nil {
			if _, ok := nameSet[p.Param.Value]; ok {
				return true
			}
		}
	case *syntax.DblQuoted:
		for _, inner := range p.Parts {
			if wordPartHasParam(inner, nameSet) {
				return true
			}
		}
	}
	return false
}

// Parse parses a single shell command string (which may be multi-line and
// contain any number of statements, pipelines, or compound commands).
//
// A parse failure returns an error and no Parsed — callers should treat this
// as "no AST, fall through to raw-string-based tiers or user prompt".
func Parse(command string) (*Parsed, error) {
	if strings.TrimSpace(command) == "" {
		return nil, errors.New("empty command")
	}

	parser := syntax.NewParser(syntax.KeepComments(true))
	file, err := parser.Parse(strings.NewReader(command), "")
	if err != nil {
		return nil, fmt.Errorf("shell parse: %w", err)
	}

	p := &Parsed{
		Raw:  command,
		File: file,
	}
	p.extract()
	return p, nil
}

func (p *Parsed) extract() {
	if len(p.File.Stmts) > 1 {
		p.Features.HasMultiStmt = true
	}

	for _, stmt := range p.File.Stmts {
		if stmt.Background {
			p.Features.HasBackground = true
		}
		if len(stmt.Redirs) > 0 {
			p.Features.HasRedirect = true
		}
		p.collectFromStmt(stmt, NestTopLevel, /*inPipeline*/ true)
	}

	// Walk the whole AST once more to pick up features from nested contexts
	// that collectFromStmt might not have reached (they're mostly also visible
	// at the top level, but this is belt-and-suspenders and catches anything
	// our collector didn't recurse into).
	syntax.Walk(p.File, func(node syntax.Node) bool {
		switch n := node.(type) {
		case *syntax.BinaryCmd:
			switch n.Op {
			case syntax.Pipe, syntax.PipeAll:
				p.Features.HasPipe = true
			case syntax.AndStmt, syntax.OrStmt:
				p.Features.HasBinaryOp = true
			}
		case *syntax.Subshell:
			p.Features.HasSubshell = true
		case *syntax.CmdSubst:
			p.Features.HasCmdSub = true
		case *syntax.ProcSubst:
			p.Features.HasProcSub = true
		case *syntax.Redirect:
			p.Features.HasRedirect = true
		}
		return true
	})

	// Also: `;` between top-level stmts counts as HasBinaryOp even though it
	// isn't a BinaryCmd — syntax.File.Stmts just contains them as separate
	// Stmt entries. Detect by: multiple top-level statements.
	if p.Features.HasMultiStmt {
		p.Features.HasBinaryOp = true
	}
}

// collectFromStmt walks a single statement, building Pipelines and Calls.
func (p *Parsed) collectFromStmt(stmt *syntax.Stmt, nesting Nesting, startPipeline bool) {
	if stmt == nil || stmt.Cmd == nil {
		return
	}

	var pipeline []Call
	p.collectFromCmd(stmt.Cmd, nesting, &pipeline)
	if startPipeline && len(pipeline) > 0 {
		p.Pipelines = append(p.Pipelines, pipeline)
	}
}

// collectFromCmd recurses into a Command, appending any CallExpr it finds to
// pipeline (for pipelines we care about) and to p.Calls.
func (p *Parsed) collectFromCmd(cmd syntax.Command, nesting Nesting, pipeline *[]Call) {
	switch c := cmd.(type) {
	case *syntax.CallExpr:
		call := resolveCall(c)
		call.Nesting = nesting
		p.Calls = append(p.Calls, call)
		if pipeline != nil {
			*pipeline = append(*pipeline, call)
		}
	case *syntax.BinaryCmd:
		switch c.Op {
		case syntax.Pipe, syntax.PipeAll:
			p.Features.HasPipe = true
			// Pipelines chain: keep collecting into the same pipeline slice.
			if c.X != nil {
				p.collectFromCmd(c.X.Cmd, nesting, pipeline)
			}
			if c.Y != nil {
				p.collectFromCmd(c.Y.Cmd, nesting, pipeline)
			}
		case syntax.AndStmt, syntax.OrStmt:
			p.Features.HasBinaryOp = true
			// && / || break the pipeline — each side is its own pipeline.
			if c.X != nil {
				var leftPipe []Call
				p.collectFromCmd(c.X.Cmd, nesting, &leftPipe)
				if len(leftPipe) > 0 && nesting == NestTopLevel {
					p.Pipelines = append(p.Pipelines, leftPipe)
				}
			}
			if c.Y != nil {
				var rightPipe []Call
				p.collectFromCmd(c.Y.Cmd, nesting, &rightPipe)
				if len(rightPipe) > 0 && nesting == NestTopLevel {
					p.Pipelines = append(p.Pipelines, rightPipe)
				}
			}
			// Signal to caller we already pushed pipelines.
			if pipeline != nil {
				*pipeline = (*pipeline)[:0]
			}
		}
	case *syntax.Subshell:
		p.Features.HasSubshell = true
		for _, stmt := range c.Stmts {
			p.collectFromStmt(stmt, NestSubshell, false)
		}
	case *syntax.Block:
		for _, stmt := range c.Stmts {
			p.collectFromStmt(stmt, nesting, false)
		}
	case *syntax.IfClause:
		p.walkBlock(c.Cond, nesting)
		p.walkBlock(c.Then, nesting)
		if c.Else != nil {
			p.walkBlock(c.Else.Cond, nesting)
			p.walkBlock(c.Else.Then, nesting)
		}
	case *syntax.ForClause:
		p.walkBlock(c.Do, nesting)
	case *syntax.WhileClause:
		p.walkBlock(c.Cond, nesting)
		p.walkBlock(c.Do, nesting)
	case *syntax.CaseClause:
		for _, item := range c.Items {
			p.walkBlock(item.Stmts, nesting)
		}
	case *syntax.FuncDecl:
		if c.Body != nil {
			p.collectFromCmd(c.Body.Cmd, nesting, nil)
		}
	}
}

func (p *Parsed) walkBlock(stmts []*syntax.Stmt, nesting Nesting) {
	for _, stmt := range stmts {
		p.collectFromStmt(stmt, nesting, false)
	}
}

// resolveCall extracts a literal Program and Args from a CallExpr, marking
// any unresolvable expansions.
func resolveCall(c *syntax.CallExpr) Call {
	call := Call{Expr: c}

	// CallExpr.Args[0] is the program; remainder are args.
	if len(c.Args) == 0 {
		// An assignment-only statement with no program (e.g. `X=1`).
		// Not a real call; return empty.
		return call
	}

	prog, progOK := resolveWord(c.Args[0])
	call.Program = prog
	if !progOK {
		call.HasUnresolved = true
	}

	for _, w := range c.Args[1:] {
		lit, ok := resolveWord(w)
		if !ok {
			call.HasUnresolved = true
		}
		call.Args = append(call.Args, lit)
		if strings.HasPrefix(lit, "-") && lit != "-" {
			call.Flags = append(call.Flags, lit)
		} else {
			call.Positional = append(call.Positional, lit)
		}
	}

	return call
}

// resolveWord attempts to flatten a Word into a literal string. Returns the
// literal and true on success. Returns partial content and false if any part
// is an unresolvable expansion (ParamExp, CmdSubst, ArithmExp).
func resolveWord(w *syntax.Word) (string, bool) {
	if w == nil {
		return "", true
	}
	var b strings.Builder
	ok := true
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			b.WriteString(p.Value)
		case *syntax.SglQuoted:
			b.WriteString(p.Value)
		case *syntax.DblQuoted:
			for _, inner := range p.Parts {
				switch ip := inner.(type) {
				case *syntax.Lit:
					b.WriteString(ip.Value)
				default:
					_ = ip
					ok = false
				}
			}
		default:
			// ParamExp, CmdSubst, ArithmExp, ProcSubst, ExtGlob — all unresolvable.
			ok = false
		}
	}
	return b.String(), ok
}
