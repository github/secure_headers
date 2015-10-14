# SecureHeaders [![Build Status](https://travis-ci.org/twitter/secureheaders.png?branch=master)](http://travis-ci.org/twitter/secureheaders) [![Code Climate](https://codeclimate.com/github/twitter/secureheaders.png)](https://codeclimate.com/github/twitter/secureheaders) [![Coverage Status](https://coveralls.io/repos/twitter/secureheaders/badge.png)](https://coveralls.io/r/twitter/secureheaders)

The gem will automatically apply several headers that are related to security.  This includes:
- Content Security Policy (CSP) - Helps detect/prevent XSS, mixed-content, and other classes of attack.  [CSP 2 Specification](http://www.w3.org/TR/CSP2/)
- HTTP Strict Transport Security (HSTS) - Ensures the browser never visits the http version of a website. Protects from SSLStrip/Firesheep attacks.  [HSTS Specification](https://tools.ietf.org/html/rfc6797)
- X-Frame-Options (XFO) - Prevents your content from being framed and potentially clickjacked. [X-Frame-Options draft](https://tools.ietf.org/html/draft-ietf-websec-x-frame-options-02)
- X-XSS-Protection - [Cross site scripting heuristic filter for IE/Chrome](http://msdn.microsoft.com/en-us/library/dd565647\(v=vs.85\).aspx)
- X-Content-Type-Options - [Prevent content type sniffing](http://msdn.microsoft.com/en-us/library/ie/gg622941\(v=vs.85\).aspx)
- X-Download-Options - [Prevent file downloads opening](http://msdn.microsoft.com/en-us/library/ie/jj542450(v=vs.85).aspx)
- X-Permitted-Cross-Domain-Policies - [Restrict Adobe Flash Player's access to data](https://www.adobe.com/devnet/adobe-media-server/articles/cross-domain-xml-for-streaming.html)
- Public Key Pinning - Pin certificate fingerprints in the browser to prevent man-in-the-middle attacks due to compromised Certificate Authorities. [Public Key Pinnning  Specification](https://tools.ietf.org/html/rfc7469)

`secure_headers` is a library with a global config, per request overrides, and rack milddleware that enables you customize your application settings.

## Configuration

**Place the following in an initializer**

All `nil` values will fallback to their default value. `SecureHeaders::OPT_OUT` will disable the header entirely.

```ruby
SecureHeaders::Configuration.configure do |config|
  config.hsts = 20.years.to_i
  config.x_frame_options = 'DENY'
  config.x_content_type_options = "nosniff"
  config.x_xss_protection = "1; mode=block"
  config.x_download_options = "noopen"
  config.x_permitted_cross_domain_policies = "none"
  config.csp = {
    :default_src => %w(https: 'self'),
    :enforce => true,
    :frame_src => %w(https: http:.twimg.com http://itunes.apple.com),
    :img_src => %w(https:),
    :connect_src => %w(wws:),
    :font_src => %w('self' data:),
    :frame_src => %w('self'),
    :img_src => %w(mycdn.com data:),
    :media_src => %w(utoob.com),
    :object_src => %w('self'),
    :script_src => %w('self'),
    :style_src => %w('unsafe-inline'),
    :base_uri => %w('self'),
    :child_src => %w('self'),
    :form_action => %w('self' github.com),
    :frame_ancestors => %w('none'),
    :plugin_types => %w(application/x-shockwave-flash),
    :block_all_mixed_content => true # see [http://www.w3.org/TR/mixed-content/]()
    :report_uri => %w(https://example.com/uri-directive)
  }
  config.hpkp = {
    :max_age => 60.days.to_i,
    :include_subdomains => true,
    :report_uri => '//example.com/uri-directive',
    :pins => [
      {:sha256 => 'abc'},
      {:sha256 => '123'}
    ]
  }
end
```

### rails 2

`secure_headers` has a `railtie` that should automatically include the middleware.

```ruby
use SecureHeaders::Middleware
```

## Default values

All headers except for PublicKeyPins have a default value. See the [corresponding classes for their defaults](https://github.com/twitter/secureheaders/tree/master/lib/secure_headers/headers).

## Per-action configuration

For the easy headers, you should not expect to change the values per request. However, for `X-Frame-Options`, `Content-Security-Policy`, and `Public-Key-Pins` you may want to configure per controller, per request, etc. values. In the future, `Public-Key-Pins` may be removed from this list.

```ruby
# Given a config of:
::SecureHeaders::Configuration.configure do |config|
 config.csp = {
   default_src: %w('self'),
   script_src: %w('self')
 }

class MyController < ApplicationController
  def index
    # Append value to the source list, override 'none' values
    # Produces: default-src 'self'; script-src 'self' s3.amazaonaws.com; object-src 'self' youtube.com
    append_content_security_policy_source(script_src: %w(s3.amazaonaws.com), object_src: %w('self' youtube.com))

    # Overrides the previously set source list, override 'none' values
    # Produces: default-src 'self'; script-src s3.amazaonaws.com; object-src 'self'
    override_content_security_policy_directive(script_src: "s3.amazaonaws.com", object_src: %w('self'))

    # Global settings default to "sameorigin"
    override_x_frame_options("DENY")

    # Disable the header if set as a global config setting
    override_hpkp(SecureHeaders::OPT_OUT)

    # Or define the hpkp inline (if the global config is nil/false)
    override_hpkp {
      :max_age => 60.days.to_i,
      :include_subdomains => true,
      :report_uri => '//example.com/uri-directive',
      :pins => [
        {:sha256 => 'abc'},
        {:sha256 => '123'}
      ]
    }
  end
```

The following methods are available as controller instance methods. They are also available as class methods, but require you to pass in the `request` object.
* `append_content_security_policy_source(hash)`: appends each value to the corresponding CSP app-wide configuration.
* `override_content_security_policy_directive(hash)`: merges the hash into the app-wide configuration, overwriting any previous config
* `override_x_frame_options(value)`: sets the `X-Frame-Options header` to `value`
* `override_hpkp(value)`: sets the `PublicKeyPins` to `value`

## Advanced override

You really shouldn't have to do this, but if you must:

```ruby
class MyController < ApplicationController
  def index
    secure_headers_request_config[:x_xss_protection] = SecureHeaders::OPT_OUT
    secure_headers_request_config[:hsts] = SecureHeaders::OPT_OUT
    secure_headers_request_config[SecureHeaders::XContentTypeOptions::CONFIG_KEY] = SecureHeaders::OPT_OUT
    secure_headers_request_config[SecureHeaders::CSP::CONFIG_KEY].merge(script_src: %w('none'))
    etc...
  end
```

#### Nonce

script/style-nonce can be used to whitelist inline content. To do this, call the SecureHeaders::content_security_policy_nonce then set the nonce attributes on the various tags.

Setting a nonce will also set 'unsafe-inline' for browsers that don't support nonces for backwards compatibility. 'unsafe-inline' is ignored if a nonce is present in a directive in compliant browsers.

```erb
<script nonce="<%= content_security_policy_nonce %>">
  console.log("whitelisted, will execute")
</script>

<script nonce="lol">
  console.log("won't execute, not whitelisted")
</script>

<script>
  console.log("won't execute, not whitelisted")
</script>
```

You can use a view helper to automatically add nonces to script tags:

```erb
<%= nonced_javascript_tag do %>
  console.log("nonced!")
<% end %>
<%= nonced_javascript_tag("nonced without a block!") %>
```

becomes:

```html
<script nonce="/jRAxuLJsDXAxqhNBB7gg7h55KETtDQBXe4ZL+xIXwI=">
console.log("nonced!")
</script>
```

#### Hash

The hash feature has been removed, for now.

### Public Key Pins

Be aware that pinning error reporting is governed by the same rules as everything else. If you have a pinning failure that tries to report back to the same origin, by definition this will not work.

```ruby
config.hpkp = {
  max_age: 60.days.to_i,   # max_age is a required parameter
  include_subdomains: true, # whether or not to apply pins to subdomains
  # Per the spec, SHA256 hashes are the only currently supported format.
  pins: [
    {sha256: 'b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c'},
    {sha256: '73a2c64f9545172c1195efb6616ca5f7afd1df6f245407cafb90de3998a1c97f'}
  ],
  enforce: true,            # defaults to false (report-only mode)
  report_uri: '//example.com/uri-directive',
  app_name: 'example',
  tag_report_uri: true
}
```

### Using with Sinatra

Here's an example using SecureHeaders for Sinatra applications:

```ruby
require 'rubygems'
require 'sinatra'
require 'haml'
require 'secure_headers'

use SecureHeaders::Middleware

SecureHeaders::Configuration.configure do |config|
  ...
end

class Donkey < Sinatra::Application
  set :root, APP_ROOT

  get '/' do
    SecureHeaders.override_x_frame_options(SecureHeaders::OPT_OUT)
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
Padrino.use(SecureHeaders::Middleware)
require 'secure_headers/padrino'

module Web
  class App < Padrino::Application
    register SecureHeaders::Padrino

    get '/' do
      render 'index'
    end
  end
end
```

and in `config/boot.rb`:

```ruby
def before_load
  SecureHeaders::Configuration.configure do |config|
    ...
  end
end
```

## Similar libraries

* Rack [rack-secure_headers](https://github.com/harmoni/rack-secure_headers)
* Node.js (express) [helmet](https://github.com/evilpacket/helmet) and [hood](https://github.com/seanmonstar/hood)
* Node.js (hapi) [blankie](https://github.com/nlf/blankie)
* J2EE Servlet >= 3.0 [headlines](https://github.com/sourceclear/headlines)
* ASP.NET - [NWebsec](https://github.com/NWebsec/NWebsec/wiki)
* Python - [django-csp](https://github.com/mozilla/django-csp) + [commonware](https://github.com/jsocol/commonware/); [django-security](https://github.com/sdelements/django-security)
* Go - [secureheader](https://github.com/kr/secureheader)

## License

Copyright 2013-2014 Twitter, Inc and other contributors.

Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0
