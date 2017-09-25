### Breaking Changes

The most likely change to break your app is the new cookie defaults. This is the first place to check. If you're using the default CSP, your policy will change but your app should not break. This should not break brand new projects using secure_headers either.

## All cookies default to secure/httponly/SameSite=Lax

By default, *all* cookies will be marked as `SameSite=lax`,`secure`, and `httponly`. To opt-out, supply `SecureHeaders::OPT_OUT` as the value for `SecureHeaders.cookies` or the individual configs. Setting these values to `false` will raise an error.

```ruby
# specific opt outs
config.cookies = {
  secure: SecureHeaders::OPT_OUT,
  httponly: SecureHeaders::OPT_OUT,
  samesite: SecureHeaders::OPT_OUT,
}

# nuclear option, just make things work again
config.cookies = SecureHeaders::OPT_OUT
```

## script_src must be set

Not setting a `script_src` value means your policy falls back to whatever `default_src` (also required) is set to. This can be very dangerous and indicates the policy is too loose. 

However, sometimes you really don't need a `script-src` e.g. API responses (`default-src 'none'`) so you can set `script_src: SecureHeaders::OPT_OUT` to work around this.

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
