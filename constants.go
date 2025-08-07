//nolint:staticcheck // no reason
package traefik_real_ip

const (
	CfConnectingIP = "Cf-Connecting-Ip"
	XRealIP        = "X-Real-IP"
	XForwardedFor  = "X-Forwarded-For"
	XIsTrusted     = "X-Is-Trusted"
)

type ContextKey string

const (
	RetryCountKey ContextKey = "retryCount"
	MaxRetryCount            = 3
)
