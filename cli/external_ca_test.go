package cli

import (
	"testing"

	"github.com/docker/swarmkit/api"
	"github.com/stretchr/testify/assert"
)

func TestParseExternalCA(t *testing.T) {
	invalidSpecs := []string{
		"",
		"asdf",
		"asdf=",
		"type",
		"type=foo",
		"type=cfssl",
		"url",
		"url=https://xyz",
		"url,type",
	}

	for _, spec := range invalidSpecs {
		_, err := parseExternalCA(spec)
		assert.Error(t, err)
	}

	validSpecs := []struct {
		input    string
		expected *api.ExternalCA
	}{
		{
			input: "type=cfssl,url=https://example.com",
			expected: &api.ExternalCA{
				Protocol: api.ExternalCA_CAProtocolCFSSL,
				URL:      "https://example.com",
				Options:  map[string]string{},
			},
		},
	}

	for _, spec := range validSpecs {
		parsed, err := parseExternalCA(spec.input)
		assert.NoError(t, err)
		assert.Equal(t, spec.expected, parsed)
	}
}