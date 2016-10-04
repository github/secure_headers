## Default values

All headers except for PublicKeyPins have a default value. See the [corresponding classes for their defaults](https://github.com/twitter/secureheaders/tree/master/lib/secure_headers/headers). The default set of headers is:

```
Content-Security-Policy: default-src 'self' https:; font-src 'self' https: data:; img-src 'self' https: data:; object-src 'none'; script-src https:; style-src 'self' https: 'unsafe-inline'
Strict-Transport-Security: max-age=631138519
X-Content-Type-Options: nosniff
X-Download-Options: noopen
X-Frame-Options: sameorigin
X-Permitted-Cross-Domain-Policies: none
X-Xss-Protection: 1; mode=block
```

### Default CSP

By default, the above CSP will be applied to all requests. If you **only** want to set a Report-Only header, opt-out of the default enforced header for clarity. The configuration will assume that if you only supply `csp_report_only` that you intended to opt-out of `csp` but that's for the sake of backwards compatibility and it will be removed in the future.

```ruby
Configuration.default do |config|
  config.csp = SecureHeaders::OPT_OUT # If this line is omitted, we will assume you meant to opt out.
  config.csp_report_only = {
    default_src: %w('self')
  }
end
```
