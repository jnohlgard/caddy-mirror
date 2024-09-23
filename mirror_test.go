package mirror

import (
	"go.uber.org/zap"
	"net/http/httptest"
	"testing"
)

func TestShouldPassThrough(t *testing.T) {
	testCases := []struct {
		method   string
		url      string
		expected bool
	}{
		{
			method:   "GET",
			url:      "http://example.com",
			expected: true,
		},
		{
			method:   "GET",
			url:      "http://example.com/download.bin",
			expected: false,
		},
		{
			method:   "GET",
			url:      "http://example.com/folder/",
			expected: true,
		},
		{
			method:   "POST",
			url:      "http://example.com/download.bin",
			expected: true,
		},
		{
			method:   "GET",
			url:      "http://example.com/some/other/file",
			expected: false,
		},
	}

	mir := Mirror{
		Root:   "/tmp/mirror_test",
		logger: zap.New(nil),
	}

	for i, test := range testCases {
		request := httptest.NewRequest(test.method, test.url, nil)
		actual := mir.shouldPassThrough(request)
		if actual != test.expected {
			t.Errorf("Test %d (method: %s, URL: %s) - expected %v, got %v",
				i, test.method, test.url, test.expected, actual)
		}
	}
}
