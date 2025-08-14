package auth_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/bootdotdev/learn-cicd-starter/internal/auth"
)

func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		input http.Header
		key   string
		err   error
	}{
		"pass":                  {input: make(http.Header), err: nil, key: "testkey"},
		"no auth header":        {input: make(http.Header), err: auth.ErrNoAuthHeaderIncluded, key: ""},
		"malformed auth header": {input: make(http.Header), err: auth.ErrMalformedAuthHeader, key: ""},
	}

	tests["pass"].input.Set("Authorization", "ApiKey "+tests["pass"].key)
	tests["malformed auth header"].input.Set("Authorization", "ApiKey")

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			key, err := auth.GetAPIKey(test.input)
			if !errors.Is(err, test.err) {
				t.Fatalf("%s: %v: %s", name, test.input.Get("Authorization"), err)
			}

			if key != test.key {
				t.Fatalf("%s: parsed key '%s' doesn't equal expected key '%s'", name, key, test.key)
			}
		})
	}
}
