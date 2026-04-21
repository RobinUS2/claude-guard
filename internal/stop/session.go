package stop

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

const maxContinuesPerSession = 3

type sessionState struct {
	Continues  int               `json:"continues"`
	Fired      map[string]string `json:"fired"`       // rule name → shell output hash
	FireCounts map[string]int    `json:"fire_counts"` // rule name → times fired
}

type session struct {
	mu   sync.Mutex
	path string
}

// newSession returns a session backed by a file in dir.
// sessionID may be empty; a stable fallback key is derived from its hash.
func newSession(sessionID, dir string) *session {
	key := sessionID
	if key == "" {
		h := sha256.Sum256([]byte("empty"))
		key = fmt.Sprintf("anon-%x", h[:4])
	}
	return &session{
		path: filepath.Join(dir, "claude-guard-stop-"+key+".json"),
	}
}

func (s *session) load() sessionState {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.path)
	if err != nil {
		return sessionState{Fired: map[string]string{}}
	}
	var st sessionState
	if err := json.Unmarshal(data, &st); err != nil || st.Fired == nil {
		return sessionState{Fired: map[string]string{}, FireCounts: map[string]int{}}
	}
	if st.FireCounts == nil {
		st.FireCounts = map[string]int{}
	}
	return st
}

func (s *session) save(st sessionState) {
	data, _ := json.Marshal(st)
	_ = os.WriteFile(s.path, data, 0o600)
}

// increment bumps the continue counter. Returns (newCount, true) if within cap,
// or (count, false) if the hard cap has been reached.
func (s *session) increment() (int, bool) {
	st := s.load()
	if st.Continues >= maxContinuesPerSession {
		return st.Continues, false
	}
	st.Continues++
	s.save(st)
	return st.Continues, true
}

func (s *session) hasFired(rule string) bool {
	st := s.load()
	_, ok := st.Fired[rule]
	return ok
}

// shellHashChanged returns true when the rule has not fired before,
// or when the current shell output hash differs from the stored one.
func (s *session) shellHashChanged(rule, currentHash string) bool {
	st := s.load()
	stored, ok := st.Fired[rule]
	if !ok {
		return true
	}
	return stored != currentHash
}

func (s *session) markFired(rule, shellHash string) {
	st := s.load()
	if st.FireCounts == nil {
		st.FireCounts = map[string]int{}
	}
	st.Fired[rule] = shellHash
	st.FireCounts[rule]++
	s.save(st)
}

// ruleFireCount returns how many times a rule has fired in this session.
func (s *session) ruleFireCount(rule string) int {
	st := s.load()
	return st.FireCounts[rule]
}

// shellHash returns a short hash of output for cool-down comparison.
func shellHash(output string) string {
	h := sha256.Sum256([]byte(output))
	return fmt.Sprintf("%x", h[:4])
}
