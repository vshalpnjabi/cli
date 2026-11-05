package shared

import (
	"bytes"
	"io"
	"net/http"
	"testing"

	"github.com/cli/cli/v2/pkg/httpmock"
	"github.com/stretchr/testify/assert"
)

func Test_HasMinimumScopes(t *testing.T) {
	tests := []struct {
		name        string
		header      string
		extraScopes []string
		wantErr     string
	}{
		{
			name:    "write:org satisfies read:org",
			header:  "repo, write:org",
			wantErr: "",
		},
		{
			name:    "insufficient scope",
			header:  "repo",
			wantErr: "missing required scope 'read:org'",
		},
		{
			name:        "with extra scope present",
			header:      "repo, read:org, workflow",
			extraScopes: []string{"workflow"},
			wantErr:     "",
		},
		{
			name:        "with extra scope missing",
			header:      "repo, read:org",
			extraScopes: []string{"workflow"},
			wantErr:     "missing required scope 'workflow'",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakehttp := &httpmock.Registry{}
			defer fakehttp.Verify(t)

			var gotAuthorization string
			fakehttp.Register(httpmock.REST("GET", ""), func(req *http.Request) (*http.Response, error) {
				gotAuthorization = req.Header.Get("authorization")
				return &http.Response{
					Request:    req,
					StatusCode: 200,
					Body:       io.NopCloser(&bytes.Buffer{}),
					Header: map[string][]string{
						"X-Oauth-Scopes": {tt.header},
					},
				}, nil
			})

			client := http.Client{Transport: fakehttp}
			err := HasMinimumScopes(&client, "github.com", "ATOKEN", tt.extraScopes...)
			if tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, gotAuthorization, "token ATOKEN")
		})
	}
}

func Test_HeaderHasMinimumScopes(t *testing.T) {
	tests := []struct {
		name        string
		header      string
		extraScopes []string
		wantErr     string
	}{
		{
			name:    "no scopes",
			header:  "",
			wantErr: "",
		},
		{
			name:    "default scopes",
			header:  "repo, read:org",
			wantErr: "",
		},
		{
			name:    "admin:org satisfies read:org",
			header:  "repo, admin:org",
			wantErr: "",
		},
		{
			name:    "write:org satisfies read:org",
			header:  "repo, write:org",
			wantErr: "",
		},
		{
			name:    "insufficient scope",
			header:  "repo",
			wantErr: "missing required scope 'read:org'",
		},
		{
			name:    "insufficient scopes",
			header:  "gist",
			wantErr: "missing required scopes 'repo', 'read:org'",
		},
		{
			name:        "extra scope present",
			header:      "repo, read:org, workflow",
			extraScopes: []string{"workflow"},
			wantErr:     "",
		},
		{
			name:        "extra scope missing",
			header:      "repo, read:org",
			extraScopes: []string{"workflow"},
			wantErr:     "missing required scope 'workflow'",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			err := HeaderHasMinimumScopes(tt.header, tt.extraScopes...)
			if tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
