package redaction_test

import (
	"testing"

	"github.com/VikingOwl91/mcp-firewall/internal/config"
	"github.com/VikingOwl91/mcp-firewall/internal/redaction"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew_ValidPatterns(t *testing.T) {
	e, err := redaction.New([]config.RedactionPattern{
		{Name: "api-key", Pattern: `sk-[a-zA-Z0-9]{32}`},
	})
	require.NoError(t, err)
	assert.NotNil(t, e)
}

func TestNew_InvalidPattern(t *testing.T) {
	_, err := redaction.New([]config.RedactionPattern{
		{Name: "bad", Pattern: `[invalid`},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bad")
}

func TestNew_Empty(t *testing.T) {
	e, err := redaction.New(nil)
	require.NoError(t, err)
	assert.NotNil(t, e)
}

func TestRedactString_Match(t *testing.T) {
	e, err := redaction.New([]config.RedactionPattern{
		{Name: "secret", Pattern: `secret-\w+`},
	})
	require.NoError(t, err)

	result, names := e.RedactString("the key is secret-abc123 here")
	assert.Equal(t, "the key is [REDACTED] here", result)
	assert.Contains(t, names, "secret")
}

func TestRedactString_NoMatch(t *testing.T) {
	e, err := redaction.New([]config.RedactionPattern{
		{Name: "secret", Pattern: `secret-\w+`},
	})
	require.NoError(t, err)

	result, names := e.RedactString("nothing to see here")
	assert.Equal(t, "nothing to see here", result)
	assert.Empty(t, names)
}

func TestRedactString_MultipleMatches(t *testing.T) {
	e, err := redaction.New([]config.RedactionPattern{
		{Name: "key", Pattern: `key-\w+`},
		{Name: "token", Pattern: `tok-\w+`},
	})
	require.NoError(t, err)

	result, names := e.RedactString("use key-abc and tok-xyz")
	assert.Equal(t, "use [REDACTED] and [REDACTED]", result)
	assert.Contains(t, names, "key")
	assert.Contains(t, names, "token")
}

func TestRedactString_ReturnsMatchedNames(t *testing.T) {
	e, err := redaction.New([]config.RedactionPattern{
		{Name: "key", Pattern: `key-\w+`},
		{Name: "token", Pattern: `tok-\w+`},
	})
	require.NoError(t, err)

	_, names := e.RedactString("only key-abc here")
	assert.Equal(t, []string{"key"}, names)
}

func TestRedactMap_StringValues(t *testing.T) {
	e, err := redaction.New([]config.RedactionPattern{
		{Name: "secret", Pattern: `secret-\w+`},
	})
	require.NoError(t, err)

	input := map[string]any{
		"password": "secret-abc123",
		"user":     "alice",
	}
	result, names := e.RedactMap(input)
	assert.Equal(t, "[REDACTED]", result["password"])
	assert.Equal(t, "alice", result["user"])
	assert.Contains(t, names, "secret")

	// Verify original is not mutated
	assert.Equal(t, "secret-abc123", input["password"])
}

func TestRedactMap_NestedMap(t *testing.T) {
	e, err := redaction.New([]config.RedactionPattern{
		{Name: "secret", Pattern: `secret-\w+`},
	})
	require.NoError(t, err)

	input := map[string]any{
		"nested": map[string]any{
			"key": "secret-deep",
		},
	}
	result, names := e.RedactMap(input)
	nested := result["nested"].(map[string]any)
	assert.Equal(t, "[REDACTED]", nested["key"])
	assert.Contains(t, names, "secret")
}

func TestRedactMap_NonStringValues(t *testing.T) {
	e, err := redaction.New([]config.RedactionPattern{
		{Name: "secret", Pattern: `secret`},
	})
	require.NoError(t, err)

	input := map[string]any{
		"count": 42,
		"flag":  true,
	}
	result, names := e.RedactMap(input)
	assert.Equal(t, 42, result["count"])
	assert.Equal(t, true, result["flag"])
	assert.Empty(t, names)
}

func TestRedactMap_Nil(t *testing.T) {
	e, err := redaction.New([]config.RedactionPattern{
		{Name: "secret", Pattern: `secret`},
	})
	require.NoError(t, err)

	result, names := e.RedactMap(nil)
	assert.Nil(t, result)
	assert.Empty(t, names)
}

func TestRedactMap_Empty(t *testing.T) {
	e, err := redaction.New([]config.RedactionPattern{
		{Name: "secret", Pattern: `secret`},
	})
	require.NoError(t, err)

	result, names := e.RedactMap(map[string]any{})
	assert.Empty(t, result)
	assert.Empty(t, names)
}

func TestRedactContent_Redacted(t *testing.T) {
	e, err := redaction.New([]config.RedactionPattern{
		{Name: "secret", Pattern: `secret-\w+`},
	})
	require.NoError(t, err)

	content := []mcp.Content{
		&mcp.TextContent{Text: "the secret-abc is here"},
	}
	result, names := e.RedactContent(content)
	text := result[0].(*mcp.TextContent)
	assert.Equal(t, "the [REDACTED] is here", text.Text)
	assert.Contains(t, names, "secret")
}

func TestRedactContent_NoMatch(t *testing.T) {
	e, err := redaction.New([]config.RedactionPattern{
		{Name: "secret", Pattern: `secret-\w+`},
	})
	require.NoError(t, err)

	content := []mcp.Content{
		&mcp.TextContent{Text: "nothing here"},
	}
	result, names := e.RedactContent(content)
	text := result[0].(*mcp.TextContent)
	assert.Equal(t, "nothing here", text.Text)
	assert.Empty(t, names)
}

func TestRedactResourceContents_Redacted(t *testing.T) {
	e, err := redaction.New([]config.RedactionPattern{
		{Name: "secret", Pattern: `secret-\w+`},
	})
	require.NoError(t, err)

	contents := []*mcp.ResourceContents{
		{URI: "test://a", Text: "data with secret-xyz"},
	}
	result, names := e.RedactResourceContents(contents)
	assert.Equal(t, "data with [REDACTED]", result[0].Text)
	assert.Equal(t, "test://a", result[0].URI)
	assert.Contains(t, names, "secret")
}

func TestRedactResourceContents_NoMatch(t *testing.T) {
	e, err := redaction.New([]config.RedactionPattern{
		{Name: "secret", Pattern: `secret-\w+`},
	})
	require.NoError(t, err)

	contents := []*mcp.ResourceContents{
		{URI: "test://a", Text: "clean data"},
	}
	result, names := e.RedactResourceContents(contents)
	assert.Equal(t, "clean data", result[0].Text)
	assert.Empty(t, names)
}
