package proxy

import (
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TruncateContent truncates text content entries to fit within maxBytes total.
// Returns the (possibly truncated) content slice and whether truncation occurred.
func TruncateContent(content []mcp.Content, maxBytes int) ([]mcp.Content, bool) {
	total := 0
	for _, c := range content {
		if tc, ok := c.(*mcp.TextContent); ok {
			total += len(tc.Text)
		}
	}

	if total <= maxBytes {
		return content, false
	}

	var result []mcp.Content
	remaining := maxBytes
	for _, c := range content {
		tc, ok := c.(*mcp.TextContent)
		if !ok {
			result = append(result, c)
			continue
		}
		if remaining <= 0 {
			break
		}
		if len(tc.Text) <= remaining {
			result = append(result, tc)
			remaining -= len(tc.Text)
		} else {
			result = append(result, &mcp.TextContent{Text: tc.Text[:remaining]})
			remaining = 0
		}
	}

	result = append(result, &mcp.TextContent{
		Text: fmt.Sprintf("\n[truncated: output exceeded limit of %d bytes]", maxBytes),
	})

	return result, true
}

// TruncateResourceContents truncates resource text contents to fit within maxBytes total.
// Returns the (possibly truncated) contents slice and whether truncation occurred.
func TruncateResourceContents(contents []*mcp.ResourceContents, maxBytes int) ([]*mcp.ResourceContents, bool) {
	total := 0
	for _, rc := range contents {
		total += len(rc.Text)
	}

	if total <= maxBytes {
		return contents, false
	}

	var result []*mcp.ResourceContents
	remaining := maxBytes
	for _, rc := range contents {
		if remaining <= 0 {
			break
		}
		if len(rc.Text) <= remaining {
			result = append(result, rc)
			remaining -= len(rc.Text)
		} else {
			result = append(result, &mcp.ResourceContents{
				URI:  rc.URI,
				Text: rc.Text[:remaining],
			})
			remaining = 0
		}
	}

	result = append(result, &mcp.ResourceContents{
		URI:  "internal://truncation-warning",
		Text: fmt.Sprintf("\n[truncated: output exceeded limit of %d bytes]", maxBytes),
	})

	return result, true
}
