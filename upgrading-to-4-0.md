### Breaking Changes

The most likely change to break your app is the new cookie defaults. This is the first place to check. If you're using the default CSP, your policy will change but your app should not break.

## All cookies default to secure/httponly

By default, *all* cookies will be marked as `SameSite=lax`,`secure`, and `httponly`. To opt-out, supply `OPT_OUT` as the value for `SecureHeaders.cookies` or the individual configs:

```ruby
# specific opt outs
config.cookies = {
  secure: OPT_OUT,
  httponly: OPT_OUT,
  samesite: OPT_OUT,
}

# nuclear option, just make things work again
config.cookies = OPT_OUT
```

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

## config.secure_cookies removed

Use `config.cookies` instead.

## Supported ruby versions

We've dropped support for ruby versions <= 2.2. Sorry.
