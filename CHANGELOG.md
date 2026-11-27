# Changelog

## Unreleased

### Breaking changes

- Middleware initialization now fails for unknown configuration keys and for nonempty
  `forwardedTrustedIPs`, `cloudflareTrustedIPs`, `cloudflareAuthHeader`, or
  `cloudflareAuthSecretFile` without `scopedTrust: true`. Correct or remove stale keys before
  upgrading. The deprecated `thrustLocal`, `thrustCloudFlare`, and `thrustEdgeOne` keys remain accepted.

### Deprecated

- Enabling `trustEdgeOne` or its alias `thrustEdgeOne` logs a startup warning. The EdgeOne IP list
  is no longer maintained. Both keys are scheduled for removal in the next minor release.
