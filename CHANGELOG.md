# Changelog

## Unreleased

### Breaking changes

- Middleware initialization now fails for unknown configuration keys and for nonempty
  `forwardedTrustedIPs`, `cloudflareTrustedIPs`, `cloudflareAuthHeader`, or
  `cloudflareAuthSecretFile` without `scopedTrust: true`. Correct or remove stale keys before
  upgrading. The deprecated `thrustLocal`, `thrustCloudFlare`, and `thrustEdgeOne` keys remain accepted.
