# Secure Headers [![Build Status](https://travis-ci.org/twitter/secureheaders.svg?branch=master)](http://travis-ci.org/twitter/secureheaders) [![Code Climate](https://codeclimate.com/github/twitter/secureheaders.svg)](https://codeclimate.com/github/twitter/secureheaders) [![Coverage Status](https://coveralls.io/repos/twitter/secureheaders/badge.svg)](https://coveralls.io/r/twitter/secureheaders)


**The 3.x branch was recently merged**. See the [upgrading to 3.x doc](upgrading-to-3-0.md) for instructions on how to upgrade including the differences and benefits of using the 3.x branch.

**The [2.x branch](https://github.com/twitter/secureheaders/tree/2.x) will be maintained**. The documentation below only applies to the 3.x branch. See the 2.x [README](https://github.com/twitter/secureheaders/blob/2.x/README.md) for the old way of doing things.

The gem will automatically apply several headers that are related to security.  This includes:
- Content Security Policy (CSP) - Helps detect/prevent XSS, mixed-content, and other classes of attack.  [CSP 2 Specification](http://www.w3.org/TR/CSP2/)
- HTTP Strict Transport Security (HSTS) - Ensures the browser never visits the http version of a website. Protects from SSLStrip/Firesheep attacks.  [HSTS Specification](https://tools.ietf.org/html/rfc6797)
- X-Frame-Options (XFO) - Prevents your content from being framed and potentially clickjacked. [X-Frame-Options Specification](https://tools.ietf.org/html/rfc7034)
- X-XSS-Protection - [Cross site scripting heuristic filter for IE/Chrome](https://msdn.microsoft.com/en-us/library/dd565647\(v=vs.85\).aspx)
- X-Content-Type-Options - [Prevent content type sniffing](https://msdn.microsoft.com/library/gg622941\(v=vs.85\).aspx)
- X-Download-Options - [Prevent file downloads opening](https://msdn.microsoft.com/library/jj542450(v=vs.85).aspx)
- X-Permitted-Cross-Domain-Policies - [Restrict Adobe Flash Player's access to data](https://www.adobe.com/devnet/adobe-media-server/articles/cross-domain-xml-for-streaming.html)
- Referrer-Policy - [Referrer Policy draft](https://w3c.github.io/webappsec-referrer-policy/)
- Public Key Pinning - Pin certificate fingerprints in the browser to prevent man-in-the-middle attacks due to compromised Certificate Authorities. [Public Key Pinning Specification](https://tools.ietf.org/html/rfc7469)

It can also mark all http cookies with the Secure, HttpOnly and SameSite attributes (when configured to do so).

`secure_headers` is a library with a global config, per request overrides, and rack middleware that enables you customize your application settings.

## Documentation

- [Getting Started](getting_started.md)
- [Base Configuration](configuration.md)
- [Named overrides and appends](named_overrides_and_appends.md)
- [Per action configuration](per_action_configuration.md)
- [Cookies](cookies.md)
- [HPKP](HPKP.md)
- [Hashes](hashes.md)

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

## License

Copyright 2013-2014 Twitter, Inc and other contributors.

Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0
