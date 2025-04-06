package traefik_real_ip

const (
	CfConnectingIP = "CF-Connecting-IP"
	XRealIP        = "X-Real-IP"
	XForwardedFor  = "X-Forwarded-For"
	XIsTrusted     = "X-Is-Trusted"
)

type ContextKey string

const (
	RetryCountKey ContextKey = "retryCount"
)
