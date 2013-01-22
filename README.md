# SecureHeaders [![Build Status](https://travis-ci.org/twitter/secureheaders.png?branch=master)](http://travis-ci.org/twitter/secureheaders) [![Code Climate](https://codeclimate.com/badge.png)](https://codeclimate.com/github/twitter/secureheaders)

The gem will automatically apply several headers that are related to security.  This includes:
- Content Security Policy (CSP) - Helps detect/prevent XSS, mixed-content, and other classes of attack.  [CSP 1.1 Specification](https://dvcs.w3.org/hg/content-security-policy/raw-file/tip/csp-specification.dev.html)
- HTTP Strict Transport Security (HSTS) - Ensures the browser never visits the http version of a website. Protects from SSLStrip/Firesheep attacks.  [HSTS Specification](https://tools.ietf.org/html/rfc6797)
- X-Frame-Options (XFO) - Prevents your content from being framed and potentially clickjacked. [X-Frame-Options draft](https://tools.ietf.org/html/draft-ietf-websec-x-frame-options-00)
- X-XSS-Protection - [Cross site scripting filter for IE](http://msdn.microsoft.com/en-us/library/dd565647\(v=vs.85\).aspx)
- X-Content-Type-Options - [Prevent content type sniffing](http://msdn.microsoft.com/en-us/library/ie/gg622941\(v=vs.85\).aspx)

## Installation

Add to your Gemfile

    gem 'secure-headers'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install secure-headers

## Usage

Functionality provided

- `ensure_security_headers`: will set security-related headers automatically based on the configuration below.

By default, it will set all of the headers listed in the options section below unless specified.

### Automagic

This gem makes a few assumptions about how you will use some features.  For example:

* It adds 'chrome-extension:' to your CSP directives by default.  This helps drastically reduce the amount of reports, but you can also disable this feature by supplying :disable_chrome_extension => true.
* It fills any blank directives with the value in :default_src  Getting a default-src report is pretty useless.  This way, you will always know what type of violation occurred. You can disable this feature by supplying :disable_fill_missing => true.
* It copies the connect-src value to xhr-src for AJAX requests.
* Firefox does not support cross-origin CSP reports.  If we are using Firefox, AND the value for :report_uri does not satisfy the same-origin requirements, we will instead forward to an internal endpoint (the forward_endpoint value or FF_CSP_ENDPOINT).  This is also the case if :report_uri only contains a path, which we assume will be cross host. This endpoint will in turn forward the request to the value in :report_uri without restriction. More information can be found in the "Note on Firefox handling of CSP" section.


## Configuration

**Place the following in an initializer:**

    ::SecureHeaders::Configuration.configure do |config|
      config.hsts = {:max_age => 99, :include_subdomains => true}
      config.x_frame_options = 'DENY'
      config.x_content_type_options = "nosniff"
      config.x_xss_protection = {:value => '1', :mode => false}
      config.csp = {
        :default_src => "https://* inline eval",
        # ALWAYS supply a full URL for report URIs
        :report_uri => 'https://example.com/uri-directive',
        :img_src => "https://* data:",
        :frame_src => "https://* http://*.twimg.com http://itunes.apple.com"
      }
    end

    # and then simply include
    ensure_security_headers

Or simply add it to application controller

    ensure_security_headers
      :hsts => {:include_subdomains, :x_frame_options => false},
      :x_frame_options => 'DENY',
      :csp => false

## Options for ensure\_security\_headers

**To disable any of these headers, supply a value of false (e.g. :hsts => false), supplying nil will set the default value**

Each header configuration can take a hash, or a string, or both. If a string
is provided, that value is inserted verbatim.  If a hash is supplied, a
header will be constructed using the supplied options.

### Widely supported

    :hsts => {:max_age => 631138519, :include_subdomain => true} # HTTP Strict Transport Security.
    :x_frame_options => {:value => 'SAMEORIGIN'}

### Content Security Policy (CSP)

All browsers will receive the webkit csp header except Firefox, which gets its own header.
See [WebKit/W3C specification](http://www.w3.org/TR/CSP/)
and [Firefox CSP specification](https://wiki.mozilla.org/Security/CSP/Specification)

    :csp => {
      :enforce     => false,        # sets header to report-only, by default
      # default_src is required!
      :default_src     => nil,      # sets the default-src/allow+options directives

      # Where reports are sent. Use full URLs.
      :report_uri  => 'https://mylogaggregator.example.com',

      # Send reports that cannot be sent across host here (see below), forward them to report_uri
      # override this if you have a route with the same value (content_security_policy#scribe)
      :forward_endpoint => TwitterRailsSecurity::Headers::ContentSecurityPolicy::FF_CSP_ENDPOINT

      # these directives all take 'none', 'self', or a globbed pattern
      :img_src     => nil,
      :frame_src   => nil,
      :connect_src => nil,
      :font_src    => nil,
      :media_src   => nil,
      :object_src  => nil,
      :style_src   => nil,
      :script_src  => nil,

      # http additions will be appended to the various directives when
      # over http, relaxing the policy
      # e.g.
      # :csp => {
      #   :img_src => 'https://*',
      #   :http_additions => {:img_src => 'http//*'}
      # }
      # would produce the directive: "img-src https://* http://*;"
      # when over http, ignored for https requests
      :http_additions => {}
    }

### Only applied to IE

    :x_content_type_options => {:value => 'nosniff'}
    :x_xss_protection       => {:value => '1', :mode => false}  # set the :mode option to block

### Example CSP header config

**Configure the CSP header as if it were the w3c-style header, no need to supply 'options' or 'allow' directives.**

    # most basic example
    :csp => {
      :default_src => "https://* inline eval",
      :report_uri => '/uri-directive'
    }
    # Chrome
    > "default-src 'unsafe-inline' 'unsafe-eval' https://* chrome-extension:; report-uri /uri-directive;"
    # Firefox
    > "options inline-script eval-script; allow https://*; report-uri /uri-directive;"

    # turn off inline scripting/eval
    :csp => {
      :default_src => 'https://*',
      :report_uri => '/uri-directive'
    }
    # Chrome
    > "default-src  https://*; report-uri /uri-directive;"
    # Firefox
    > "allow https://*; report-uri /uri-directive;"

    # Auction site wants to allow images from anywhere, plugin content from a list of trusted media providers (including a content distribution network), and scripts only from its server hosting sanitized JavaScript
    :csp => {
      :default_src => 'self',
      :img_src => '*',
      :object_src => ['media1.com', 'media2.com', '*.cdn.com'],
      # alternatively (NOT csv) :object_src => 'media1.com media2.com *.cdn.com'
      :script_src => 'trustedscripts.example.com'
    }
    # Chrome
    "default-src  'self'; img-src *; object-src media1.com media2.com *.cdn.com; script-src trustedscripts.example.com;"
    # Firefox
    "allow 'self'; img-src *; object-src media1.com media2.com *.cdn.com; script-src trustedscripts.example.com;"

## Note on Firefox handling of CSP

Currently, Firefox does not support the w3c draft standard.  So there are a few steps taken to make the two interchangeable.

Firefox > 18 partially supports the standard via using the default-src directive over allow/options, but the following inconsistencies remain.

* inline-script or eval-script values in default/style/script-src directives are moved to the options directive. Note: the style-src directive is not fully supported in Firefox - see https://bugzilla.mozilla.org/show_bug.cgi?id=763879.
* CSP reports will not POST cross-origin.  This sets up an internal endpoint in the application that will forward the request. Set the "forward_endpoint" value in the CSP section if you need to post cross origin for firefox.
* Firefox adds port numbers to each /https?/ value which can make local development tricky with mocked services. Add environment specific code to configure this.

### Adding the Firefox report forwarding endpoint

**You need to add the following line to the TOP of confib/routes.rb**
**This is an unauthenticated, unauthorized endpoint. Only do this if your report-uri is not on the same origin as your application!!!**

If you need to change the route for the internal forwarding point, be sure it matches what is set in :forward_endpoint or else the reports will post to a non-existent endpoint.

#### Rails 2

    map.csp_endpoint

#### Rails 3

If the csp reporting endpoint is clobbered by another route, add:

    match SecureHeaders::ContentSecurityPolicy::FF_CSP_ENDPOINT => "content_security_policy#scribe"

## Authors

* Neil Matatall [@ndm](https://twitter.com/ndm) - primary author.
* Nicholas Green [@nickgreen](https://twitter.com/nickgreen) - code contributions, main reviewer.

## Acknowledgements

* Justin Collins [@presidentbeef](https://twitter.com/presidentbeef) & Jim O'Leary [@jimio](https://twitter.com/jimio) for reviews.
* Ian Melven [@imelven](https://twitter.com/imelven) - Discussions/info about CSP in general, made us aware of the [userCSP](https://addons.mozilla.org/en-US/firefox/addon/newusercspdesign/) Firefox extension.
* Sumit Shah [@omnidactyl](https://twitter.com/omnidactyl) - For being an eager guinea pig.
* Chris Aniszczyk [@cra](https://twitter.com/cra) - For running an awesome open source program at Twitter.

## License

Copyright 2013 Twitter, Inc.

Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0
