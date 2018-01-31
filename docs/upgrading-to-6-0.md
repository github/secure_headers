## Named overrides are now dynamically applied

The original implementation of name overrides worked by making a copy of the default policy, applying the overrides, and storing the result for later use. But, this lead to unexpected results if named overrides were combined with a dynamic policy change. If a change was made to the default configuration during a request, followed by a named override, the dynamic changes would be lost. To keep things consistent named overrides have been rewritten to work the same as named appends in that they always operate on the configuration for the current request. As an example:

```ruby
# specific opt outs
Configuration.default do |config|
  config.x_frame_options = OPT_OUT
end

# Dynamically update the default config for this request
SecureHeaders.override_x_frame_options(request, "DENY")

SecureHeaders::Configuration.override(:dynamic_override) do |config|
  config.x_content_type_options = "nosniff"
end

SecureHeaders.use_secure_headers_override(request, :dynamic_override)
```

Prior to 6.0.0, the response would NOT include an `X-Frame-Options` header since the named override would be a copy of the default configuration, but with `X-Content-Type-Options` set to `nosniff`. As of 6.0.0, the above code results in both `X-Frame-Options` set to `DENY` AND `X-Content-Type-Options` to `nosniff`.

## `ContentSecurityPolicyConfig#merge` and `ContentSecurityPolicyReportOnlyConfig#merge` work more like `Hash#merge`

These classes are typically not directly instantiated by users of SecureHeaders. But, if you access `config.csp` you end up accessing one of these objects. Prior to 6.0.0, `#merge` worked more like `#append` in that it would combine policies (i.e. if both policies contained the same key the values would be combined rather than overwritten). This was not consistent with `#merge!`, which worked more like ruby's `Hash#merge!` (overwriting duplicate keys). As of 6.0.0, `#merge` works the same as `#merge!`, but returns a new object instead of mutating `self`.

## `Configuration#get` has been removed

This method is not typically directly called by users of SecureHeaders. Given that named overrides are no longer statically stored, fetching them no longer makes sense.

## Configuration headers are no longer cached

Prior to 6.0.0 SecureHeaders prebuilt and cached the headers that corresponded to the default configuration. The same was also done for named overrides. However, now that named overrides are applied dynamically, those can no longer be cached. As a result, caching has been removed in the name of simplicity. Some micro-benchmarks indicate this shouldn't be a performmance problem and will help to elimiate a class of bugs entirely.
