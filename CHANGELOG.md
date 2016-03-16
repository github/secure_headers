## 3.0.3

Bug fix for handling policy merges where appending a non-default source value (report-uri, plugin-types, frame-ancestors, base-uri, and form-action) would be combined with the default-src value. Appending a directive that doesn't exist in the current policy combines the new value with `default-src` to mimic the actual behavior of the addition. However, this does not make sense for non-default-src values (a.k.a. "fetch directives") and can lead to unexpected behavior like a `report-uri` value of `*`. Previously, this config:

```
{
  default_src => %w(*)
}
```

When appending:

```
{
  report_uri => %w(https://report-uri.io/asdf)
}
```

Would result in `default-src *; report-uri *` which doesn't make any sense at all.

## 3.0.2

Bug fix for handling CSP configs that supply a frozen hash. If a directive value is `nil`, then appending to a config with a frozen hash would cause an error since we're trying to modify a frozen hash. See https://github.com/twitter/secureheaders/pull/223.

## 3.0.1

Adds `upgrade-insecure-requests` support for requests from Firefox and Chrome (and Opera). See [the spec](https://www.w3.org/TR/upgrade-insecure-requests/) for details.

## 3.0.0

secure_headers 3.0.0 is a near-complete, not-entirely-backward-compatible rewrite. Please see the [upgrade guide](https://github.com/twitter/secureheaders/blob/master/upgrading-to-3-0.md) for an in-depth explanation of the changes and the suggested upgrade path.

## 2.5.1 - 2016-02-16 18:11:11 UTC - Remove noisy deprecation warning

See https://github.com/twitter/secureheaders/issues/203 and https://github.com/twitter/secureheaders/commit/cfad0e52285353b88e46fe384e7cd60bf2a01735

>> Upon upgrading to secure_headers 2.5.0, I get a flood of these deprecations when running my tests:
> [DEPRECATION] secure_header_options_for will not be supported in secure_headers

/cc @bquorning

## 2.5.0 - 2016-01-06 22:11:02 UTC - 2.x deprecation warning release

This release contains deprecation warnings for those wishing to upgrade to the 3.x series. With this release, fixing all deprecation warnings will make your configuration compatible when you decide to upgrade to the soon-to-be-released 3.x series (currently in pre-release stage).

No changes to functionality should be observed unless you were using procs as CSP config values.

## 2.4.4 - 2015-12-03 23:29:42 UTC - Bug fix release

If you use the `header_hash` method for setting your headers in middleware and you opted out of a header (via setting the value to `false`), you would run into an exception as described in https://github.com/twitter/secureheaders/pull/193

```
     NoMethodError:
       undefined method `name' for nil:NilClass
     # ./lib/secure_headers.rb:63:in `block in header_hash'
     # ./lib/secure_headers.rb:54:in `each'
     # ./lib/secure_headers.rb:54:in `inject'
     # ./lib/secure_headers.rb:54:in `header_hash'
```


## 2.4.3 - 2015-10-23 18:35:43 UTC - Performance improvement

@igrep reported an anti-patter in use regarding [UserAgentParser](https://github.com/ua-parser/uap-ruby). This caused UserAgentParser to reload it's entire configuration set *twice** per request. Moving this to a cached constant prevents the constant reinstantiation and will improve performance.

https://github.com/twitter/secureheaders/issues/187

## 2.4.2 - 2015-10-20 20:22:08 UTC - Bug fix release

A nasty regression meant that many CSP configuration values were "reset" after the first request, one of these being the "enforce" flag. See https://github.com/twitter/secureheaders/pull/184 for the full list of fields that were affected. Thanks to @spdawson for reporting this https://github.com/twitter/secureheaders/issues/183

## 2.4.1 - 2015-10-14 22:57:41 UTC - More UA sniffing

This release may change the output of headers based on per browser support. Unsupported directives will be omitted based on the user agent per request. See https://github.com/twitter/secureheaders/pull/179

p.s. this will likely be the last non-bugfix release for the 2.x line. 3.x will be a major change. Sneak preview: https://github.com/twitter/secureheaders/pull/181

## 2.4.0 - 2015-10-01 23:05:38 UTC - Some internal changes affecting behavior, but not functionality

If you leveraged `secure_headers` automatic filling of empty directives, the header value will change but it should not affect how the browser applies the policy. The content of CSP reports may change if you do not update your policy.

before
===

```ruby
  config.csp = {
    :default_src => "'self'"
  }
```
would produce `default-src 'self'; connect-src 'self'; frame-src 'self' ... etc.`

after
===

```ruby
  config.csp = {
    :default_src => "'self'"
  }
```

will produce `default-src 'self'`

The reason for this is that a `default-src` violation was basically impossible to handle. Chrome sends an `effective-directive` which helps indicate what kind of violation occurred even if it fell back to `default-src`. This is part of the [CSP Level 2 spec](http://www.w3.org/TR/CSP2/#violation-report-effective-directive) so hopefully other browsers will implement this soon.

Workaround
===

Just set the values yourself, but really a `default-src` of anything other than `'none'` implies the policy can be tightened dramatically. "ZOMG don't you work for github and doesn't github send a `default-src` of `*`???" Yes, this is true. I disagree with this but at the same time, github defines every single known directive that a browser supports so `default-src` will only apply if a new directive is introduced, and we'd rather fail open. For now.

```ruby
  config.csp = {
    :default_src => "'self'",
    :connect_src => "'self'",
    :frame_src => "'self'"
    ... etc.
  }
```

Besides, relying on `default-src` is often not what you want and encourages an overly permissive policy. I've seen it. Seriously. `default-src 'unsafe-inline' 'unsafe-eval' https: http:;` That's terrible.


## 2.3.0 - 2015-09-30 19:43:09 UTC - Add header_hash feature for use in middleware.

See https://github.com/twitter/secureheaders/issues/167 and https://github.com/twitter/secureheaders/pull/168

tl;dr is that there is a class method `SecureHeaders::header_hash` that will return a hash of header name => value pairs useful for merging with the rack header hash in middleware.

## 2.2.4 - 2015-08-26 23:31:37 UTC - Print deprecation warning for 1.8.7 users

As discussed in https://github.com/twitter/secureheaders/issues/154

## 2.2.3 - 2015-08-14 20:26:12 UTC - Adds ability to opt-out of automatically adding data: sources to img-src

See https://github.com/twitter/secureheaders/pull/161

## 2.2.2 - 2015-07-02 21:18:38 UTC - Another option for config granularity.

See https://github.com/twitter/secureheaders/pull/147

Allows you to override a controller method that returns a config in the context of the executing action.

## 2.2.1 - 2015-06-24 21:01:57 UTC - When using nonces, do not include the nonce for safari / IE

See https://github.com/twitter/secureheaders/pull/150

Safari will generate a warning that it doesn't support nonces. Safari will fall back to the `unsafe-inline`. Things will still work, but an ugly message is printed to the console.

This opts out safari and IE users from the inline script protection. I haven't verified any IE behavior yet, so I'm just assuming it doesn't work.

## 2.2.0 - 2015-06-18 22:01:23 UTC - Pass controller reference to callable config value expressions.

https://github.com/twitter/secureheaders/pull/148

Facilitates better per-request config:

 `:enforce => lambda { |controller| controller.current_user.beta_testing? }`

**NOTE** if you used `lambda` config values, this will raise an exception until you add the controller reference:

bad:

`lambda { true }`

good:

`lambda { |controller| true }`
`proc { true }`
`proc { |controller| true }`

## v2.1.0 - 2015-05-07 18:34:56 UTC - Add hpkp support

Includes https://github.com/twitter/secureheaders/pull/143 (which is really just https://github.com/twitter/secureheaders/pull/132) from @thirstscolr


## v2.0.2 - 2015-05-05 03:09:44 UTC - Add report_uri constant value

Just a small change that adds a constant that was missing as reported in https://github.com/twitter/secureheaders/issues/141

## v2.0.1 - 2015-03-20 18:46:47 UTC - View Helpers Fixed

Fixes an issue where view helpers (for nonces, hashes, etc) weren't available in views.

## 2.0.0 - 2015-01-23 20:23:56 UTC - 2.0

This release contains support for more csp level 2 features such as the new directives, the script hash integration, and more.

It also sets a new header by default: `X-Permitted-Cross-Domain-Policies`

Support for hpkp is not included in this release as the implementations are still very unstable.

:rocket:

## v.2.0.0.pre2 - 2014-12-06 01:55:42 UTC - Adds X-Permitted-Cross-Domain-Policies support by default

The only change between this and the first pre release is that the X-Permitted-Cross-Domain-Policies support is included.

## v1.4.0 - 2014-12-06 01:54:48 UTC - Deprecate features in preparation for 2.0

This removes the forwarder and "experimental" feature. The forwarder wasn't well maintained and created a lot of headaches. Also, it was using an outdated certificate pack for compatibility. That's bad. The experimental feature wasn't really used and it complicated the codebase a lot. It's also a questionably useful API that is very confusing.

## v2.0.0.pre - 2014-11-14 00:54:07 UTC - 2.0.0.pre - CSP level 2 support

This release is intended to be ready for CSP level 2. Mainly, this means there is direct support for hash/nonce of inline content and includes many new directives (which do not inherit from default-src)

## v1.3.4 - 2014-10-13 22:05:44 UTC -

* Adds X-Download-Options support
* Adds support for X-XSS-Protection reporting
* Defers loading of rails engine for faster boot times

## v1.3.3 - 2014-08-15 02:30:24 UTC - hsts preload confirmation value support

@agl just made a new option for HSTS representing confirmation that a site wants to be included in a browser's preload list (https://hstspreload.appspot.com).

This just adds a new 'preload' option to the HSTS settings to specify that option.

## v1.3.2 - 2014-08-14 00:01:32 UTC - Add app tagging support

Tagging Requests

It's often valuable to send extra information in the report uri that is not available in the reports themselves. Namely, "was the policy enforced" and "where did the report come from"
```ruby
{
  :tag_report_uri => true,
  :enforce => true,
  :app_name => 'twitter',
  :report_uri => 'csp_reports'
}
```
Results in
```
report-uri csp_reports?enforce=true&app_name=twitter
```
