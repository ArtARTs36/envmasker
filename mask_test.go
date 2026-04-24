package envmasker

import "testing"

func TestMaskSensitiveKeysWholeValue(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
	}{
		{"database url", "DATABASE_URL", "postgres://user:pass@db:5432/app"},
		{"db password", "DB_PASSWORD", "supersecret"},
		{"postgres password", "POSTGRES_PASSWORD", "supersecret"},
		{"pg password", "PGPASSWORD", "supersecret"},
		{"mysql url", "MYSQL_URL", "mysql://user:pass@db/app"},
		{"mongo uri", "MONGODB_URI", "mongodb://user:pass@mongo/app"},
		{"redis url", "REDIS_URL", "redis://:pass@redis:6379/0"},
		{"sentry dsn", "SENTRY_DSN", "https://abc123@sentry.example/1"},
		{"connection string", "DATABASE_CONNECTION_STRING", "Server=db;User Id=u;Password=p;"},
		{"api key", "SERVICE_API_KEY", "key-123"},
		{"hyphenated secret", "service-token", "token-123"},
		{"dotted secret", "service.secret", "secret-123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Mask(tt.key, tt.value)
			if !ok {
				t.Fatalf("Mask(%q, %q) ok=false, want true", tt.key, tt.value)
			}
			if got != MaskValue {
				t.Fatalf("Mask(%q, %q) = %q, want %q", tt.key, tt.value, got, MaskValue)
			}
		})
	}
}

func TestMaskDoesNotMaskClearlyNonSensitiveKeys(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
	}{
		{"log level", "LOG_LEVEL", "debug"},
		{"public url", "PUBLIC_URL", "https://example.com/callback"},
		{"base url", "BASE_URL", "https://api.example.com"},
		{"host", "DB_HOST", "postgres"},
		{"port", "DB_PORT", "5432"},
		{"empty value with sensitive key", "DB_PASSWORD", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Mask(tt.key, tt.value)
			if ok {
				t.Fatalf("Mask(%q, %q) ok=true, want false", tt.key, tt.value)
			}
			if got != tt.value {
				t.Fatalf("Mask(%q, %q) = %q, want %q", tt.key, tt.value, got, tt.value)
			}
		})
	}
}

func TestMaskDSNValuesInNonSensitiveFields(t *testing.T) {
	tests := []struct {
		name string
		key  string
		in   string
		want string
	}{
		{
			name: "command database url arg",
			key:  "COMMAND",
			in:   "app --database-url=postgres://user:pass@db/app --log-level=debug",
			want: "app --database-url=**** --log-level=debug",
		},
		{
			name: "bare postgres dsn",
			key:  "COMMAND",
			in:   "connect postgres://user:pass@db:5432/app now",
			want: "connect postgres://**** now",
		},
		{
			name: "bare mongodb srv dsn",
			key:  "COMMAND",
			in:   "mongodb+srv://user:pass@cluster.example/db?retryWrites=true",
			want: "mongodb+srv://****",
		},
		{
			name: "bare redis dsn",
			key:  "COMMAND",
			in:   "redis://:pass@redis:6379/0",
			want: "redis://****",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Mask(tt.key, tt.in)
			if !ok {
				t.Fatalf("Mask(%q, %q) ok=false, want true", tt.key, tt.in)
			}
			if got != tt.want {
				t.Fatalf("Mask(%q, %q) = %q, want %q", tt.key, tt.in, got, tt.want)
			}
		})
	}
}

func TestMaskURLUserInfoInNonSensitiveFields(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "https basic auth",
			in:   "https://user:pass@example.com/path",
			want: "https://****:****@example.com/path",
		},
		{
			name: "https user only",
			in:   "https://token@example.com/path",
			want: "https://****:****@example.com/path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Mask("PUBLIC_URL", tt.in)
			if !ok {
				t.Fatalf("Mask(PUBLIC_URL, %q) ok=false, want true", tt.in)
			}
			if got != tt.want {
				t.Fatalf("Mask(PUBLIC_URL, %q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestMaskKnownTokenShapes(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "jwt",
			in:   "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature_123",
			want: "Authorization: Bearer ****",
		},
		{
			name: "aws access key",
			in:   "AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF",
			want: "AWS_ACCESS_KEY_ID=****",
		},
		{
			name: "github token",
			in:   "token ghp_abcdefghijklmnopqrstuvwxyz1234567890",
			want: "token ****",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Mask("COMMAND", tt.in)
			if !ok {
				t.Fatalf("Mask(COMMAND, %q) ok=false, want true", tt.in)
			}
			if got != tt.want {
				t.Fatalf("Mask(COMMAND, %q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestMaskInlineSecretArgs(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "equals form",
			in:   "server --password=supersecret --user=app",
			want: "server --password=**** --user=app",
		},
		{
			name: "space form",
			in:   "server --token supersecret --user app",
			want: "server --token **** --user app",
		},
		{
			name: "single dash",
			in:   "server -secret=supersecret",
			want: "server -secret=****",
		},
		{
			name: "no dash assignment",
			in:   "token=supersecret log=debug",
			want: "token=**** log=debug",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Mask("COMMAND", tt.in)
			if !ok {
				t.Fatalf("Mask(COMMAND, %q) ok=false, want true", tt.in)
			}
			if got != tt.want {
				t.Fatalf("Mask(COMMAND, %q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestMaskQueryParams(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "token param",
			in:   "https://example.com/callback?token=abc123&state=ok",
			want: "https://example.com/callback?token=****&state=ok",
		},
		{
			name: "api key param",
			in:   "https://example.com/path?x=1&api_key=abc123",
			want: "https://example.com/path?x=1&api_key=****",
		},
		{
			name: "password param",
			in:   "https://example.com/path?password=abc123#frag",
			want: "https://example.com/path?password=****#frag",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Mask("PUBLIC_URL", tt.in)
			if !ok {
				t.Fatalf("Mask(PUBLIC_URL, %q) ok=false, want true", tt.in)
			}
			if got != tt.want {
				t.Fatalf("Mask(PUBLIC_URL, %q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestMaskTrimsKey(t *testing.T) {
	got, ok := Mask("  DB_PASSWORD  ", "supersecret")
	if !ok {
		t.Fatal("Mask should report ok=true")
	}
	if got != MaskValue {
		t.Fatalf("got %q, want %q", got, MaskValue)
	}
}
