package envmasker

import (
	"regexp"
	"strings"
)

const MaskValue = "****"

var (
	// Keys whose value should be masked completely.
	// We intentionally do not mask every *_URL: PUBLIC_URL, BASE_URL,
	// CALLBACK_URL are often not secrets. DB/cache DSNs and URLs are covered.
	sensitiveKeyRe = regexp.MustCompile(`(?i)(^|[_\-.])(` +
		`pgpassword|pgpass|pguser|pgdatabase|pass(word)?|pwd|secret|token|access[_\-.]?token|refresh[_\-.]?token|` +
		`api[_\-.]?key|private[_\-.]?key|credential(s)?|auth|` +
		`dsn|uri|connection[_\-.]?string|` +
		`database[_\-.]?url|db[_\-.]?url|postgres(?:ql)?[_\-.]?url|pg[_\-.]?url|` +
		`mysql[_\-.]?url|mariadb[_\-.]?url|mongo(db)?[_\-.]?(url|uri)|redis[_\-.]?url|` +
		`sentry[_\-.]?dsn` +
		`)([_\-.]|$)`)

	// Bare DB/cache/broker DSNs in arbitrary text.
	dsnValueRe = regexp.MustCompile(`(?i)\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp|amqps|clickhouse)://)[^\s'"<>]+`)

	// user:password@ inside URLs.
	urlUserInfoRe = regexp.MustCompile(`(?i)\b((?:https?|postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp|amqps|clickhouse)://)([^:/@\s]+)(?::([^@\s]+))?@`)

	// JWT.
	jwtRe = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`)

	// AWS Access Key ID.
	awsAccessKeyRe = regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`)

	// GitHub tokens: ghp_, gho_, ghu_, ghs_, ghr_.
	githubTokenRe = regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9_]{30,}\b`)

	// Inline flags:
	// --password=xxx
	// --password xxx
	// -password=xxx
	// token=xxx
	inlineSecretArgRe = regexp.MustCompile(`(?i)(\b-{0,2}(?:password|pass|pwd|secret|token|api-key|apikey|dsn|database-url|db-url|redis-url|mongo-uri|mongodb-uri)(?:\s*=\s*|\s+))([^\s'"<>&#]+)`)

	// Secret query params:
	// ?password=xxx&sslmode=require
	// &token=xxx
	querySecretRe = regexp.MustCompile(`(?i)([?&](?:password|pass|pwd|secret|token|access_token|refresh_token|api_key|apikey|key)=)([^&#\s'"<>]+)`)
)

// Mask masks a variable/field value using both key-based and value-based rules.
//
// It returns:
//   - maskedValue: original or masked value
//   - masked: true if masking was applied
func Mask(key string, value string) (maskedValue string, masked bool) {
	key = strings.TrimSpace(key)

	if key == "" && value == "" {
		return value, false
	}

	// If the key name is clearly sensitive, hide the entire value.
	if sensitiveKeyRe.MatchString(key) {
		if value == "" {
			return value, false
		}
		return MaskValue, true
	}

	original := value
	maskedValue = value

	// Mask userinfo first so even normal https://user:pass@host is cleaned.
	maskedValue = urlUserInfoRe.ReplaceAllString(maskedValue, `${1}`+MaskValue+`:`+MaskValue+`@`)

	// Then mask full DB/cache/broker DSNs.
	maskedValue = dsnValueRe.ReplaceAllString(maskedValue, `${1}`+MaskValue)

	// Token and key-looking values.
	maskedValue = jwtRe.ReplaceAllString(maskedValue, MaskValue)
	maskedValue = awsAccessKeyRe.ReplaceAllString(maskedValue, MaskValue)
	maskedValue = githubTokenRe.ReplaceAllString(maskedValue, MaskValue)

	// Inline args and query params.
	maskedValue = inlineSecretArgRe.ReplaceAllString(maskedValue, `${1}`+MaskValue)
	maskedValue = querySecretRe.ReplaceAllString(maskedValue, `${1}`+MaskValue)

	return maskedValue, maskedValue != original
}
