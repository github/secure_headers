## X-Xss-Protection is set to 0 by default

Version 6 and below of `secure_headers` set the `X-Xss-Protection` to `1; mode=block` by default. This was done to protect against reflected XSS attacks. However, this header is no longer recommended (see https://github.com/github/secure_headers/issues/439 for more information).

If any functionality in your app depended on this header being set to the previous value, you will need to set it explicitly in your configuration.

```ruby
# config/initializers/secure_headers.rb
SecureHeaders::Configuration.default do |config|
  config.x_xss_protection = "1; mode=block"
end
```