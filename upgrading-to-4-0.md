### Breaking Changes

## Default Content Security Policy

The default CSP has changed to be more universal without sacrificing too much security.

* Flash/Java disabled by default
* `img-src` allows data: images and favicons (among others)
* `style-src` allows inline CSS by default (most find it impossible/impractical to remove inline content today)
* `form-action` (not governed by `default-src`, practically treated as `*`) is set to `'self'`

Previously, the default CSP was:

`Content-Security-Policy: default-src 'self'`

The new default policy is:

`default-src https:; form-action 'self'; img-src https: data: 'self'; object-src 'none'; script-src https:; style-src 'self' 'unsafe-inline' https:`

## CSP configuration

* Setting `report_only: true` in a CSP config will raise an error. Instead, set `csp_report_only`.
* Setting `frame_src` and `child_src` when values don't match will raise an error. Just use `frame_src`.


## All cookies default to secure/httponly

By default, all cookies will be marked as `secure` and `httponly`. To opt-out, supply `OPT_OUT` as the value for `SecureHeaders.cookies` or the individual configs:

```ruby
config.cookies = {
  secure: OPT_OUT,
  httponly: OPT_OUT,
}
```

## config.secure_cookies removed

Use `config.cookies` instead.

## Supported ruby versions

We've dropped support for ruby versions <= 2.2. Sorry.
