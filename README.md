# Secure Headers [![Build Status](https://travis-ci.org/twitter/secureheaders.svg?branch=master)](http://travis-ci.org/twitter/secureheaders) [![Code Climate](https://codeclimate.com/github/twitter/secureheaders.svg)](https://codeclimate.com/github/twitter/secureheaders) [![Coverage Status](https://coveralls.io/repos/twitter/secureheaders/badge.svg)](https://coveralls.io/r/twitter/secureheaders)


**The 3.x branch was recently merged**. See the [upgrading to 3.x doc](upgrading-to-3-0.md) for instructions on how to upgrade including the differences and benefits of using the 3.x branch.

**The [2.x branch](https://github.com/twitter/secureheaders/tree/2.x) will be maintained**. The documentation below only applies to the 3.x branch. See the 2.x [README](https://github.com/twitter/secureheaders/blob/2.x/README.md) for the old way of doing things.

The gem will automatically apply several headers that are related to security.  This includes:
- Content Security Policy (CSP) - Helps detect/prevent XSS, mixed-content, and other classes of attack.  [CSP 2 Specification](http://www.w3.org/TR/CSP2/)
  - https://csp.withgoogle.com
  - https://csp.withgoogle.com/docs/strict-csp.html
  - https://csp-evaluator.withgoogle.com
- HTTP Strict Transport Security (HSTS) - Ensures the browser never visits the http version of a website. Protects from SSLStrip/Firesheep attacks.  [HSTS Specification](https://tools.ietf.org/html/rfc6797)
- X-Frame-Options (XFO) - Prevents your content from being framed and potentially clickjacked. [X-Frame-Options Specification](https://tools.ietf.org/html/rfc7034)
- X-XSS-Protection - [Cross site scripting heuristic filter for IE/Chrome](https://msdn.microsoft.com/en-us/library/dd565647\(v=vs.85\).aspx)
- X-Content-Type-Options - [Prevent content type sniffing](https://msdn.microsoft.com/library/gg622941\(v=vs.85\).aspx)
- X-Download-Options - [Prevent file downloads opening](https://msdn.microsoft.com/library/jj542450(v=vs.85).aspx)
- X-Permitted-Cross-Domain-Policies - [Restrict Adobe Flash Player's access to data](https://www.adobe.com/devnet/adobe-media-server/articles/cross-domain-xml-for-streaming.html)
- Referrer-Policy - [Referrer Policy draft](https://w3c.github.io/webappsec-referrer-policy/)
- Public Key Pinning - Pin certificate fingerprints in the browser to prevent man-in-the-middle attacks due to compromised Certificate Authorities. [Public Key Pinning Specification](https://tools.ietf.org/html/rfc7469)
- Expect-CT - Only use certificates that are present in the certificate transparency logs. [Expect-CT draft specification](https://datatracker.ietf.org/doc/draft-stark-expect-ct/).
- Clear-Site-Data - Clearing browser data for origin. [Clear-Site-Data specification](https://w3c.github.io/webappsec-clear-site-data/).

It can also mark all http cookies with the Secure, HttpOnly and SameSite attributes (when configured to do so).

`secure_headers` is a library with a global config, per request overrides, and rack middleware that enables you customize your application settings.

## Documentation

- [Named overrides and appends](docs/named_overrides_and_appends.md)
- [Per action configuration](docs/per_action_configuration.md)
- [Cookies](docs/cookies.md)
- [HPKP](docs/HPKP.md)
- [Hashes](docs/hashes.md)
- [Sinatra Config](docs/sinatra.md)

## Getting Started

### Rails 3+

For Rails 3+ applications, `secure_headers` has a `railtie` that should automatically include the middleware. If for some reason the middleware is not being included follow the instructions for Rails 2.

### Rails 2

For Rails 2 or non-rails applications, an explicit statement is required to use the middleware component.

```ruby
use SecureHeaders::Middleware
```

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
  # Add "; preload" and submit the site to hstspreload.org for best protection.
  config.hsts = "max-age=#{20.years.to_i}; includeSubdomains"
  config.x_frame_options = "DENY"
  config.x_content_type_options = "nosniff"
  config.x_xss_protection = "1; mode=block"
  config.x_download_options = "noopen"
  config.x_permitted_cross_domain_policies = "none"
  config.referrer_policy = "origin-when-cross-origin"
  config.clear_site_data = [
    "cache",
    "cookies",
    "storage",
    "executionContexts"
  ]
  config.expect_certificate_transparency = {
    enforce: false,
    max_age: 1.day.to_i,
    report_uri: "https://report-uri.io/example-ct"
  }
  config.csp = {
    # "meta" values. these will shaped the header, but the values are not included in the header.
    # report_only: true,      # default: false [DEPRECATED from 3.5.0: instead, configure csp_report_only]
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
    manifest_src: %w('self'),
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

All headers except for PublicKeyPins and ClearSiteData have a default value. The default set of headers is:

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


## Similar libraries

* Rack [rack-secure_headers](https://github.com/frodsan/rack-secure_headers)
* Node.js (express) [helmet](https://github.com/helmetjs/helmet) and [hood](https://github.com/seanmonstar/hood)
* Node.js (hapi) [blankie](https://github.com/nlf/blankie)
* J2EE Servlet >= 3.0 [headlines](https://github.com/sourceclear/headlines)
* ASP.NET - [NWebsec](https://github.com/NWebsec/NWebsec/wiki)
* Python - [django-csp](https://github.com/mozilla/django-csp) + [commonware](https://github.com/jsocol/commonware/); [django-security](https://github.com/sdelements/django-security)
* Go - [secureheader](https://github.com/kr/secureheader)
* Elixir [secure_headers](https://github.com/anotherhale/secure_headers)
* Dropwizard [dropwizard-web-security](https://github.com/palantir/dropwizard-web-security)
* Ember.js [ember-cli-content-security-policy](https://github.com/rwjblue/ember-cli-content-security-policy/)
* PHP [secure-headers](https://github.com/BePsvPT/secure-headers)

## License

Copyright 2013-2014 Twitter, Inc and other contributors.

Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0
