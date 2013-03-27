# SecureHeaders [![Build Status](https://travis-ci.org/twitter/secureheaders.png?branch=master)](http://travis-ci.org/twitter/secureheaders) [![Code Climate](https://codeclimate.com/github/twitter/secureheaders.png)](https://codeclimate.com/github/twitter/secureheaders)

The gem will automatically apply several headers that are related to security.  This includes:
- Content Security Policy (CSP) - Helps detect/prevent XSS, mixed-content, and other classes of attack.  [CSP 1.1 Specification](https://dvcs.w3.org/hg/content-security-policy/raw-file/tip/csp-specification.dev.html)
- HTTP Strict Transport Security (HSTS) - Ensures the browser never visits the http version of a website. Protects from SSLStrip/Firesheep attacks.  [HSTS Specification](https://tools.ietf.org/html/rfc6797)
- X-Frame-Options (XFO) - Prevents your content from being framed and potentially clickjacked. [X-Frame-Options draft](https://tools.ietf.org/html/draft-ietf-websec-x-frame-options-00)
- X-XSS-Protection - [Cross site scripting heuristic filter for IE/Chrome](http://msdn.microsoft.com/en-us/library/dd565647\(v=vs.85\).aspx)
- X-Content-Type-Options - [Prevent content type sniffing](http://msdn.microsoft.com/en-us/library/ie/gg622941\(v=vs.85\).aspx)

This gem has integration with Rails, but works for any Ruby code. See the sinatra example section.

## Installation

Add to your Gemfile

```ruby
gem 'secure_headers'
```

And then execute:

```console
$ bundle
```

Or install it yourself as:

```console
$ gem install secure_headers
```

## Usage

Functionality provided

- `ensure_security_headers`: will set security-related headers automatically based on the configuration below.

By default, it will set all of the headers listed in the options section below unless specified.

### Automagic

This gem makes a few assumptions about how you will use some features.  For example:

* It adds 'chrome-extension:' to your CSP directives by default.  This helps drastically reduce the amount of reports, but you can also disable this feature by supplying :disable_chrome_extension => true.
* It fills any blank directives with the value in :default_src  Getting a default\-src report is pretty useless.  This way, you will always know what type of violation occurred. You can disable this feature by supplying :disable_fill_missing => true.
* It copies the connect\-src value to xhr\-src for AJAX requests.
* Firefox does not support cross\-origin CSP reports.  If we are using Firefox, AND the value for :report_uri does not satisfy the same\-origin requirements, we will instead forward to an internal endpoint (`FF_CSP_ENDPOINT`).  This is also the case if :report_uri only contains a path, which we assume will be cross host. This endpoint will in turn forward the request to the value in :forward_endpoint without restriction. More information can be found in the "Note on Firefox handling of CSP" section.


## Configuration

**Place the following in an initializer (recommended):**

```ruby
::SecureHeaders::Configuration.configure do |config|
  config.hsts = {:max_age => 99, :include_subdomains => true}
  config.x_frame_options = 'DENY'
  config.x_content_type_options = "nosniff"
  config.x_xss_protection = {:value => 1, :mode => false}
  config.csp = {
    :default_src => "https://* inline eval",
    :report_uri => '//example.com/uri-directive',
    :img_src => "https://* data:",
    :frame_src => "https://* http://*.twimg.com http://itunes.apple.com"
  }
end

# and then simply include
ensure_security_headers
```

Or simply add it to application controller (not recommended, currently a bug)

```ruby
ensure_security_headers
  :hsts => {:include_subdomains, :x_frame_options => false},
  :x_frame_options => 'DENY',
  :csp => false
```

## Options for ensure\_security\_headers

**To disable any of these headers, supply a value of false (e.g. :hsts => false), supplying nil will set the default value**

Each header configuration can take a hash, or a string, or both. If a string
is provided, that value is inserted verbatim.  If a hash is supplied, a
header will be constructed using the supplied options.

### Widely supported

```ruby
:hsts             => {:max_age => 631138519, :include_subdomain => true}
:x_frame_options  => {:value => 'SAMEORIGIN'}
:x_xss_protection => {:value => 1, :mode => false}  # set the :mode option to 'block' to enforce the browser's xss filter
```

### Content Security Policy (CSP)

All browsers will receive the webkit csp header except Firefox, which gets its own header.
See [WebKit specification](http://www.w3.org/TR/CSP/)
and [Mozilla CSP specification](https://wiki.mozilla.org/Security/CSP/Specification)

```ruby
:csp => {
  :enforce     => false,        # sets header to report-only, by default
  # default_src is required!
  :default_src     => nil,      # sets the default-src/allow+options directives

  # Where reports are sent. Use protocol relative URLs if you are posting to the same domain (TLD+1). Use paths if you are posting to the application serving the header
  :report_uri  => '//mysite.example.com',

  # Send reports that cannot be sent across host here. These requests are sent
  # the server, not the browser. If no value is supplied, it will default to
  # the value in report_uri. Use this if you cannot use relative protocols mentioned above due to host mismatches.
  :forward_endpoint => 'https://internal.mylogaggregator.example.com'

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

  # If you have enforce => true, you can use the `experiments` block to
  # also produce a report-only header. Values in this block override the
  # parent config for the report-only, and leave the enforcing header
  # unaltered. http_additions work the same way described above, but
  # are added to your report-only header as expected.
  :experimental => {
    :script_src => 'self',
    :img_src => 'https://mycdn.example.com',
    :http_additions {
      :img_src => 'http://mycdn.example.com'
    }
  }
}
```

### Only applied to IE

```ruby
:x_content_type_options => {:value => 'nosniff'}
```

### Example CSP header config

**Configure the CSP header as if it were the webkit-style header, no need to supply 'options' or 'allow' directives.**

```ruby
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
```

## Note on Firefox handling of CSP

Currently, Firefox does not support the w3c draft standard.  So there are a few steps taken to make the two interchangeable.

* inline\-script or eval\-script values in default/style/script\-src directives are moved to the options directive. Note: the style\-src directive is not fully supported in Firefox \- see https://bugzilla.mozilla.org/show_bug.cgi?id=763879.
* CSP reports will not POST cross\-origin.  This sets up an internal endpoint in the application that will forward the request. Set the `forward_endpoint` value in the CSP section if you need to post cross origin for firefox. The internal endpoint that receives the initial request will forward the request to `forward_endpoint`
* Ffirefox adds port numbers to each /https?/ value which can make local development tricky with mocked services. Add environment specific code to configure this.

### Adding the Firefox report forwarding endpoint

**You need to add the following line to the TOP of confib/routes.rb**
**This is an unauthenticated, unauthorized endpoint. Only do this if your report\-uri is not on the same origin as your application!!!**

#### Rails 2

```ruby
map.csp_endpoint
```

#### Rails 3

If the csp reporting endpoint is clobbered by another route, add:

```ruby
post SecureHeaders::ContentSecurityPolicy::FF_CSP_ENDPOINT => "content_security_policy#scribe"
```
### Using with Sinatra

Here's an example using SecureHeaders for Sinatra applications:

```ruby
require 'rubygems'
require 'sinatra'
require 'haml'
require 'secure_headers'

::SecureHeaders::Configuration.configure do |config|
  config.hsts = {:max_age => 99, :include_subdomains => true}
  config.x_frame_options = 'DENY'
  config.x_content_type_options = "nosniff"
  config.x_xss_protection = {:value => 1, :mode => false}
  config.csp = {
    :default_src => "https://* inline eval",
    :report_uri => '//example.com/uri-directive',
    :img_src => "https://* data:",
    :frame_src => "https://* http://*.twimg.com http://itunes.apple.com"
  }
end

class Donkey < Sinatra::Application
  include SecureHeaders
  set :root, APP_ROOT

  get '/' do
    set_csp_header(request, nil)
    haml :index
  end
end
```

### Using with Padrino

You can use SecureHeaders for Padrino applications as well:

In your `Gemfile`:

```ruby
  gem "secure_headers", :require => 'secure_headers'
```

then in your `app.rb` file you can:

```ruby
module Web
  class App < Padrino::Application
    include SecureHeaders

    ::SecureHeaders::Configuration.configure do |config|
      config.hsts                   = {:max_age => 99, :include_subdomains => true}
      config.x_frame_options        = 'DENY'
      config.x_content_type_options = "nosniff"
      config.x_xss_protection       = {:value   => '1', :mode => false}
      config.csp                    = {
        :default_src => "https://* inline eval",
        :report_uri => '//example.com/uri-directive',
        :img_src => "https://* data:",
        :frame_src => "https://* http://*.twimg.com http://itunes.apple.com"
      }
    end

    get '/' do
      set_csp_header(request, nil)
      render 'index'
    end
  end
end
```


## Authors

* Neil Matatall [@ndm](https://twitter.com/ndm) - primary author.
* Nicholas Green [@nickgreen](https://twitter.com/nickgreen) - code contributions, main reviewer.

## Acknowledgements

* Justin Collins [@presidentbeef](https://twitter.com/presidentbeef) & Jim O'Leary [@jimio](https://twitter.com/jimio) for reviews.
* Ian Melven [@imelven](https://twitter.com/imelven) - Discussions/info about CSP in general, made us aware of the [userCSP](https://addons.mozilla.org/en-US/firefox/addon/newusercspdesign/) Mozilla extension.
* Sumit Shah [@omnidactyl](https://twitter.com/omnidactyl) - For being an eager guinea pig.
* Chris Aniszczyk [@cra](https://twitter.com/cra) - For running an awesome open source program at Twitter.

## License

Copyright 2013 Twitter, Inc.

Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0
