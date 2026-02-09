package redaction

import (
	"fmt"
	"regexp"

	"github.com/VikingOwl91/mcp-firewall/internal/config"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type compiledPattern struct {
	name string
	re   *regexp.Regexp
}

type Engine struct {
	patterns []compiledPattern
}

func New(patterns []config.RedactionPattern) (*Engine, error) {
	compiled := make([]compiledPattern, 0, len(patterns))
	for _, p := range patterns {
		re, err := regexp.Compile(p.Pattern)
		if err != nil {
			return nil, fmt.Errorf("compiling redaction pattern %q: %w", p.Name, err)
		}
		compiled = append(compiled, compiledPattern{name: p.Name, re: re})
	}
	return &Engine{patterns: compiled}, nil
}

func (e *Engine) RedactString(s string) (string, []string) {
	var matched []string
	for _, p := range e.patterns {
		if p.re.MatchString(s) {
			s = p.re.ReplaceAllString(s, "[REDACTED]")
			matched = append(matched, p.name)
		}
	}
	return s, matched
}

func (e *Engine) RedactMap(m map[string]any) (map[string]any, []string) {
	if m == nil {
		return nil, nil
	}
	result := make(map[string]any, len(m))
	var allMatched []string
	for k, v := range m {
		switch val := v.(type) {
		case string:
			redacted, matched := e.RedactString(val)
			result[k] = redacted
			allMatched = appendUnique(allMatched, matched)
		case map[string]any:
			redacted, matched := e.RedactMap(val)
			result[k] = redacted
			allMatched = appendUnique(allMatched, matched)
		default:
			result[k] = v
		}
	}
	return result, allMatched
}

func (e *Engine) RedactContent(content []mcp.Content) ([]mcp.Content, []string) {
	result := make([]mcp.Content, len(content))
	var allMatched []string
	for i, c := range content {
		tc, ok := c.(*mcp.TextContent)
		if !ok {
			result[i] = c
			continue
		}
		redacted, matched := e.RedactString(tc.Text)
		result[i] = &mcp.TextContent{Text: redacted}
		allMatched = appendUnique(allMatched, matched)
	}
	return result, allMatched
}

func (e *Engine) RedactResourceContents(contents []*mcp.ResourceContents) ([]*mcp.ResourceContents, []string) {
	result := make([]*mcp.ResourceContents, len(contents))
	var allMatched []string
	for i, rc := range contents {
		redacted, matched := e.RedactString(rc.Text)
		result[i] = &mcp.ResourceContents{
			URI:      rc.URI,
			MIMEType: rc.MIMEType,
			Text:     redacted,
			Blob:     rc.Blob,
		}
		allMatched = appendUnique(allMatched, matched)
	}
	return result, allMatched
}

func appendUnique(dst, src []string) []string {
	seen := make(map[string]bool, len(dst))
	for _, s := range dst {
		seen[s] = true
	}
	for _, s := range src {
		if !seen[s] {
			dst = append(dst, s)
			seen[s] = true
		}
	}
	return dst
}
