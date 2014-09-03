1.3.3
======

@agl just made a new option for HSTS representing confirmation that a site wants to be included in a browser's preload list (https://hstspreload.appspot.com).

This just adds a new 'preload' option to the HSTS settings to specify that option.

1.3.2
======

Adds the ability to "tag" requests and a new config value: :app_name

{
  :tag_report_uri => true,
  :enforce => true,
  :app_name => 'twitter',
  :report_uri => 'csp_reports'
}

Results in
report-uri csp_reports?enforce=true&app_name=twitter


1.3.1
======

Bugfix release: same-origin detection would error out when the URL containined invalid values (like |)

1.3.0
======

- CSP nonce support was added back and is compliant.
- Bugs:
-- enforce, disable_fill_missing, and disable_chrome_extension did not accept lambdas for no good reason
-- IF a default-src was specified, and an img-src was not, and disable_fill_missing was true, the img-src value would be :data

1.2.0
======
- Allow procs to be used as config values.

1.1.1
======

Bug fix release.
- Parsing of CSP reports was busted.
- Forwarded reports did not include the original referer, ip, UA

1.1.0
======

- Remove brwsr dependency (no more runtime dependencies)
- Stop serving X- prefixed CSP headers

This change means that all requests get all headers, even if the browser doesn't grok it.

1.0.0
======

Features:

- Use non-prefixed header names for Firefox >= 23, Chrome >= 25
- Use csp 1.0 compliant header for firefox >= 23

Bug Fix:

- Stop sending CSP on safari 5.1+

0.5.0
======

- X-Content-Type-Options also applied to Chrome requests

0.4.3
======

- Safari 5 is just completely broken when CSP is used, both mobile and desktop versions

0.4.2
======

- Stupid bug where Fixnums couldn't be used for config values
- Doc updates

0.4.1
======

- Allow strings or ints in the HSTS max-age (@reedloden)

0.4.0
=======

- Treat each header as it's own before_filter. This allows you to `skip_before_filter :set_X_header, :only => :bad_idea
- Should be backwards compatible, but it is a change to the API.

0.3.0
=======

- Greatly reduce the need to use the forward_endpoint attribute. If you are posting from your site to a host that matches TLD+1 (e.g. translate.twitter.com matches twitter.com), use a protocol relative value for report-uri. This will alleviate the need to use forwarding. If your host doesn't match, you still need to use forwarding due to host mismatches for Firefox.

0.2.3
=======

- Fix error in report-uri logic for Firefox forwarding.

0.2.2
=======

- Stop applying chrome-extension: to Firefox directives.

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
