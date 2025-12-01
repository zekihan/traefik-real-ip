package traefik_real_ip

const (
	CfConnectingIP = "Cf-Connecting-Ip"
	EoConnectingIP = "Eo-Connecting-Ip"
	XRealIP        = "X-Real-IP"
	XForwardedFor  = "X-Forwarded-For"
	XIsTrusted     = "X-Is-Trusted"
)

type ContextKey string

const RetryCountKey ContextKey = "retryCount"

const MaxRetryCount = 3
