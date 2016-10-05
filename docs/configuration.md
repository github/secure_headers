## Configuration

If you do not supply a `default` configuration, exceptions will be raised. If you would like to use a default configuration (which is fairly locked down), just call `SecureHeaders::Configuration.default` without any arguments or block.

All `nil` values will fallback to their default values. `SecureHeaders::OPT_OUT` will disable the header entirely.

```ruby
SecureHeaders::Configuration.default do |config|
  config.cookies = {
    secure: true, # mark all cookies as "Secure"
    httponly: true, # mark all cookies as "HttpOnly"
    samesite: {
      lax: true # mark all cookies as SameSite=lax
    }
  }
  config.hsts = "max-age=#{20.years.to_i}; includeSubdomains; preload"
  config.x_frame_options = "DENY"
  config.x_content_type_options = "nosniff"
  config.x_xss_protection = "1; mode=block"
  config.x_download_options = "noopen"
  config.x_permitted_cross_domain_policies = "none"
  config.referrer_policy = "origin-when-cross-origin"
  config.csp = {
    # "meta" values. these will shaped the header, but the values are not included in the header.
    report_only: true,      # default: false [DEPRECATED from 3.5.0: instead, configure csp_report_only]
    preserve_schemes: true, # default: false. Schemes are removed from host sources to save bytes and discourage mixed content.

    # directive values: these values will directly translate into source directives
    default_src: %w(https: 'self'),
    base_uri: %w('self'),
    block_all_mixed_content: true, # see http://www.w3.org/TR/mixed-content/
    child_src: %w('self'), # if child-src isn't supported, the value for frame-src will be set.
    connect_src: %w(wss:),
    font_src: %w('self' data:),
    form_action: %w('self' github.com),
    frame_ancestors: %w('none'),
    img_src: %w(mycdn.com data:),
    media_src: %w(utoob.com),
    object_src: %w('self'),
    plugin_types: %w(application/x-shockwave-flash),
    script_src: %w('self'),
    style_src: %w('unsafe-inline'),
    upgrade_insecure_requests: true, # see https://www.w3.org/TR/upgrade-insecure-requests/
    report_uri: %w(https://report-uri.io/example-csp)
  }
  # This is available only from 3.5.0; use the `report_only: true` setting for 3.4.1 and below.
  config.csp_report_only = config.csp.merge({
    img_src: %w(somewhereelse.com),
    report_uri: %w(https://report-uri.io/example-csp-report-only)
  })
  config.hpkp = {
    report_only: false,
    max_age: 60.days.to_i,
    include_subdomains: true,
    report_uri: "https://report-uri.io/example-hpkp",
    pins: [
      {sha256: "abc"},
      {sha256: "123"}
    ]
  }
end
```

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
