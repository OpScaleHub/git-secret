package config

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Matches reports whether relPath (repo-relative, either slash style) is
// selected for encryption: it must match at least one entry in Patterns
// and none in Exclude.
func (c *Config) Matches(relPath string) (bool, error) {
	relPath = filepath.ToSlash(relPath)

	matched := false
	for _, p := range c.Patterns {
		ok, err := matchGlob(p, relPath)
		if err != nil {
			return false, fmt.Errorf("config: pattern %q: %w", p, err)
		}
		if ok {
			matched = true
			break
		}
	}
	if !matched {
		return false, nil
	}

	for _, e := range c.Exclude {
		ok, err := matchGlob(e, relPath)
		if err != nil {
			return false, fmt.Errorf("config: exclude %q: %w", e, err)
		}
		if ok {
			return false, nil
		}
	}
	return true, nil
}

// matchGlob matches a gitignore-style glob against a slash-separated path.
// A "**" path segment matches zero or more whole segments; other segments
// are matched with filepath.Match (supporting *, ?, and [...] within a
// single segment).
//
// A leading "/" is stripped first: patterns are always repo-root-relative
// (there's no other base they could match against), so "/secrets/**" and
// "secrets/**" are the same pattern. Without this, splitting "/secrets/**"
// on "/" produces a leading empty segment that can never match a real path
// segment, silently failing every match — a natural typo that otherwise
// makes a pattern validate cleanly while matching nothing (hooks/verify
// fail open with no error).
func matchGlob(pattern, path string) (bool, error) {
	pattern = strings.TrimPrefix(pattern, "/")
	return matchSegments(strings.Split(pattern, "/"), strings.Split(path, "/"))
}

func matchSegments(pat, path []string) (bool, error) {
	if len(pat) == 0 {
		return len(path) == 0, nil
	}
	if pat[0] == "**" {
		if len(pat) == 1 {
			return true, nil
		}
		for i := 0; i <= len(path); i++ {
			ok, err := matchSegments(pat[1:], path[i:])
			if err != nil {
				return false, err
			}
			if ok {
				return true, nil
			}
		}
		return false, nil
	}
	if len(path) == 0 {
		return false, nil
	}
	ok, err := filepath.Match(pat[0], path[0])
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}
	return matchSegments(pat[1:], path[1:])
}

// lastSegment is used by Validate to sanity-check pattern syntax without
// needing a real path to match against.
func lastSegment(pattern string) string {
	segs := strings.Split(pattern, "/")
	return segs[len(segs)-1]
}
