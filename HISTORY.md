0.2.1
=======

- Firefox headers will now stop overriding report_uri when only a path is supplied

0.2.0
=======

- 0.1.0 introduced a serious regression in which child controllers overwrote parent controller config values
- Decoupling of CSP headers and the request object. Allows you to generate static values to save cycles:

```ruby
FIREFOX = SecureHeaders::ContentSecurityPolicy.new(config, :ua => "Firefox", :ssl => true).value
CHROME = SecureHeaders::ContentSecurityPolicy.new(config, :ua => "Chrome", :ssl => true).value
```
- :forward_endpoint now acts as the endpoint that reports are forwarded to (when using the internal forwarder feature for cross-host reporting)
- Skeleton applications have been added to test isolated application configurations
- Cleanup by @bemurphy

0.1.1
=======

Bug fix. Firefox doesn't seem to like the default-src directive, reverting back to 'allow'

0.1.0
=======

Notes:
------

- Gem is renamed to secure_headers. This will make bundler happy. https://github.com/twitter/secureheaders/pull/26

Features:
------

- ability to apply two headers, one in enforce mode, one in "experimental" mode https://github.com/twitter/secureheaders/pull/11
- Rails 3.0 support https://github.com/twitter/secureheaders/pull/28

Bug fixes, misc:
------

- Fix issue where settings in application_controller were ignored if no intializer was supplied https://github.com/twitter/secureheaders/pull/25
- Better support for other frameworks, including docs from @achui, @bmaland
- Rails 4 routes support from @jviney https://github.com/twitter/secureheaders/pull/13
- data: automatically whitelisted for img-src
- Doc updates from @ming13, @theverything, @dcollazo
