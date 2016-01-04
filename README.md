# SecureHeaders [![Build Status](https://travis-ci.org/twitter/secureheaders.png?branch=master)](http://travis-ci.org/twitter/secureheaders) [![Code Climate](https://codeclimate.com/github/twitter/secureheaders.png)](https://codeclimate.com/github/twitter/secureheaders) [![Coverage Status](https://coveralls.io/repos/twitter/secureheaders/badge.png)](https://coveralls.io/r/twitter/secureheaders)

**The 3.x branch was recently merged**. See the [upgrading to 3.x doc](upgrading-to-3-0.md) for instructions on how to upgrade including the differences and benefits of using the 3.x branch.

**The [2.x branch](https://github.com/twitter/secureheaders/tree/2.x) will be maintained**. The documentation below only applies to the 2.x branch. See the 2.x [README](https://github.com/twitter/secureheaders/blob/2.x/README.md) for the old way of doing things.

The gem will automatically apply several headers that are related to security.  This includes:
- Content Security Policy (CSP) - Helps detect/prevent XSS, mixed-content, and other classes of attack.  [CSP 2 Specification](http://www.w3.org/TR/CSP2/)
- HTTP Strict Transport Security (HSTS) - Ensures the browser never visits the http version of a website. Protects from SSLStrip/Firesheep attacks.  [HSTS Specification](https://tools.ietf.org/html/rfc6797)
- X-Frame-Options (XFO) - Prevents your content from being framed and potentially clickjacked. [X-Frame-Options draft](https://tools.ietf.org/html/draft-ietf-websec-x-frame-options-02)
- X-XSS-Protection - [Cross site scripting heuristic filter for IE/Chrome](http://msdn.microsoft.com/en-us/library/dd565647\(v=vs.85\).aspx)
- X-Content-Type-Options - [Prevent content type sniffing](http://msdn.microsoft.com/en-us/library/ie/gg622941\(v=vs.85\).aspx)
- X-Download-Options - [Prevent file downloads opening](http://msdn.microsoft.com/en-us/library/ie/jj542450(v=vs.85).aspx)
- X-Permitted-Cross-Domain-Policies - [Restrict Adobe Flash Player's access to data](https://www.adobe.com/devnet/adobe-media-server/articles/cross-domain-xml-for-streaming.html)
- Public Key Pinning - Pin certificate fingerprints in the browser to prevent man-in-the-middle attacks due to compromised Certificate Authorities. [Public Key Pinning Specification](https://tools.ietf.org/html/rfc7469)

`secure_headers` is a library with a global config, per request overrides, and rack milddleware that enables you customize your application settings.

## Configuration

If you do not supply a `default` configuration, exceptions will be raised. If you would like to use a default configuration (which is fairly locked down), just call `SecureHeaders::Configuration.default` without any arguments or block.

All `nil` values will fallback to their default value. `SecureHeaders::OPT_OUT` will disable the header entirely.

```ruby
SecureHeaders::Configuration.default do |config|
  config.hsts = "max-age=#{20.years.to_i}"
  config.x_frame_options = "DENY"
  config.x_content_type_options = "nosniff"
  config.x_xss_protection = "1; mode=block"
  config.x_download_options = "noopen"
  config.x_permitted_cross_domain_policies = "none"
  config.csp = {
    default_src: %w(https: 'self'),
    report_only: false,
    frame_src: %w(*.twimg.com itunes.apple.com),
    connect_src: %w(wws:),
    font_src: %w('self' data:),
    frame_src: %w('self'),
    img_src: %w(mycdn.com data:),
    media_src: %w(utoob.com),
    object_src: %w('self'),
    script_src: %w('self'),
    style_src: %w('unsafe-inline'),
    base_uri: %w('self'),
    child_src: %w('self'),
    form_action: %w('self' github.com),
    frame_ancestors: %w('none'),
    plugin_types: %w(application/x-shockwave-flash),
    block_all_mixed_content: true, # see [http://www.w3.org/TR/mixed-content/](http://www.w3.org/TR/mixed-content/)
    report_uri: %w(https://example.com/uri-directive)
  }
  config.hpkp = {
    report_only: false,
    max_age: 60.days.to_i,
    include_subdomains: true,
    report_uri: "https://example.com/uri-directive",
    pins: [
      {sha256: "abc"},
      {sha256: "123"}
    ]
  }
end
```

### rails 2

For rails 3+ applications, `secure_headers` has a `railtie` that should automatically include the middleware. For rails 2 applications, an explicit statement is required to use the middleware component.

```ruby
use SecureHeaders::Middleware
```

## Default values

All headers except for PublicKeyPins have a default value. See the [corresponding classes for their defaults](https://github.com/twitter/secureheaders/tree/master/lib/secure_headers/headers).

## Named overrides

Named overrides serve two purposes:

* To be able to refer to a configuration by simple name.
* By precomputing the headers for a named configuration, the headers generated once and reused over every request.

To use a named override, drop a `SecureHeaders::Configuration.override` block **outside** of method definitions and then declare which named override you'd like to use. You can even override an override.

```ruby
class ApplicationController < ActionController::Base
  SecureHeaders::Configuration.default do |config|
    config.csp = {
      default_src: %w('self'),
      script_src: %w(example.org)
    }
  end

  # override default configuration
  SecureHeaders::Configuration.override(:script_from_otherdomain_com) do |config|
    config.csp[:script_src] << "otherdomain.com"
  end

  # overrides the :script_from_otherdomain_com configuration
  SecureHeaders::Configuration.override(:another_config, :script_from_otherdomain_com) do |config|
    config.csp[:script_src] << "evenanotherdomain.com"
  end
end

class MyController < ApplicationController
  def index
    # Produces default-src 'self'; script-src example.org otherdomain.org
    use_secure_headers_override(:script_from_otherdomain_com)
  end

  def show
    # Produces default-src 'self'; script-src example.org otherdomain.org evenanotherdomain.com
    use_secure_headers_override(:another_config)
  end
end
```

By default, a noop configuration is provided. No headers will be set when this default override is used.

```ruby
class MyController < ApplicationController
  def index
    SecureHeaders::opt_out_of_all_protection(request)
  end
end
```

## Per-action configuration

You can override the settings for a given action by producing a temporary override. This approach is not recommended because the header values will be computed per request.

```ruby
# Given a config of:
::SecureHeaders::Configuration.default do |config|
   config.csp = {
     default_src: %w('self'),
     script_src: %w('self')
   }
 end

class MyController < ApplicationController
  def index
    # Append value to the source list, override 'none' values
    # Produces: default-src 'self'; script-src 'self' s3.amazaonaws.com; object-src 'self' youtube.com
    append_content_security_policy_directives(script_src: %w(s3.amazaonaws.com), object_src: %w('self' youtube.com))

    # Overrides the previously set source list, override 'none' values
    # Produces: default-src 'self'; script-src s3.amazaonaws.com; object-src 'self'
    override_content_security_policy_directives(script_src: %w(s3.amazaonaws.com), object_src: %w('self'))

    # Global settings default to "sameorigin"
    override_x_frame_options("DENY")
  end
```

The following methods are available as controller instance methods. They are also available as class methods, but require you to pass in the `request` object.
* `append_content_security_policy_directives(hash)`: appends each value to the corresponding CSP app-wide configuration.
* `override_content_security_policy_directives(hash)`: merges the hash into the app-wide configuration, overwriting any previous config
* `override_x_frame_options(value)`: sets the `X-Frame-Options header` to `value`

## Appending / overriding Content Security Policy

When manipulating content security policy, there are a few things to consider. The default header value is `default-src https:` which corresponds to a default configuration of `{ default_src: %w(https:)}`.

#### Append to the policy with a directive other than `default_src`

The value of `default_src` is joined with the addition. Note the `https:` is carried over from the `default-src` config. If you do not want this, use `override_content_security_policy_directives` instead. To illustrate:

```ruby
::SecureHeaders::Configuration.configure do |config|
   config.csp = {
     default_src: %w('self')
   }
 end
 ```

Code  | Result
------------- | -------------
`append_content_security_policy_directives(script_src: %w(mycdn.com))` | `default-src 'self'; script-src 'self' mycdn.com`
`override_content_security_policy_directives(script_src: %w(mycdn.com))`  | `default-src 'self'; script-src mycdn.com`

Code  | Result
------------- | -------------
`append_content_security_policy_directives(script_src: %w(mycdn.com))` | `default-src https:; script-src https: mycdn.com`
`override_content_security_policy_directives(script_src: %w(mycdn.com))`  | `default-src https:; script-src mycdn.com`

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
console.log("hai");
<% end %>

<%= nonced_style_tag do %>
body {
  background-color: black;
}
<% end %>
```

becomes:

```html
<script nonce="/jRAxuLJsDXAxqhNBB7gg7h55KETtDQBXe4ZL+xIXwI=">
console.log("nonced!")
</script>
<style nonce="/jRAxuLJsDXAxqhNBB7gg7h55KETtDQBXe4ZL+xIXwI=">
body {
  background-color: black;
}
</style>
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
  report_only: true,            # defaults to false (report-only mode)
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
  gem "secure_headers", require: 'secure_headers'
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
