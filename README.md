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

## Use

`gem install secure_headers`

## Configuration

If you do not supply a `default` configuration, exceptions will be raised. If you would like to use a default configuration (which is fairly locked down), just call `SecureHeaders::Configuration.default` without any arguments or block.

All `nil` values will fallback to their default values. `SecureHeaders::OPT_OUT` will disable the header entirely.

```ruby
SecureHeaders::Configuration.default do |config|
  config.cookies = {
    secure: true, # mark all cookies as "Secure"
    httponly: true, # mark all cookies as "HttpOnly"
    samesite: {
      strict: true # mark all cookies as SameSite=Strict
    }
  }
  config.hsts = "max-age=#{20.years.to_i}; includeSubdomains; preload"
  config.x_frame_options = "DENY"
  config.x_content_type_options = "nosniff"
  config.x_xss_protection = "1; mode=block"
  config.x_download_options = "noopen"
  config.x_permitted_cross_domain_policies = "none"
  config.referrer_policy = "origin-when-cross-origin"
  config.csp = {
    # "meta" values. these will shaped the header, but the values are not included in the header.
    report_only: true,      # default: false
    preserve_schemes: true, # default: false. Schemes are removed from host sources to save bytes and discourage mixed content.

    # directive values: these values will directly translate into source directives
    default_src: %w(https: 'self'),
    base_uri: %w('self'),
    block_all_mixed_content: true, # see http://www.w3.org/TR/mixed-content/
    child_src: %w('self'), # if child-src isn't supported, the value for frame-src will be set.
    connect_src: %w(wss:),
    font_src: %w('self' data:),
    form_action: %w('self' github.com),
    frame_ancestors: %w('none'),
    img_src: %w(mycdn.com data:),
    media_src: %w(utoob.com),
    object_src: %w('self'),
    plugin_types: %w(application/x-shockwave-flash),
    script_src: %w('self'),
    style_src: %w('unsafe-inline'),
    upgrade_insecure_requests: true, # see https://www.w3.org/TR/upgrade-insecure-requests/
    report_uri: %w(https://report-uri.io/example-csp)
  }
  config.hpkp = {
    report_only: false,
    max_age: 60.days.to_i,
    include_subdomains: true,
    report_uri: "https://report-uri.io/example-hpkp",
    pins: [
      {sha256: "abc"},
      {sha256: "123"}
    ]
  }
end
```

### rails 2

For rails 3+ applications, `secure_headers` has a `railtie` that should automatically include the middleware. For rails 2 or non-rails applications, an explicit statement is required to use the middleware component.

```ruby
use SecureHeaders::Middleware
```

## Default values

All headers except for PublicKeyPins have a default value. See the [corresponding classes for their defaults](https://github.com/twitter/secureheaders/tree/master/lib/secure_headers/headers).

## Named Appends

Named Appends are blocks of code that can be reused and composed during requests. e.g. If a certain partial is rendered conditionally, and the csp needs to be adjusted for that partial, you can create a named append for that situation. The value returned by the block will be passed into `append_content_security_policy_directives`. The current request object is passed as an argument to the block for even more flexibility.

```ruby
def show
  if include_widget?
    @widget = widget.render
    use_content_security_policy_named_append(:widget_partial)
  end
end


SecureHeaders::Configuration.named_append(:widget_partial) do |request|
  SecureHeaders.override_x_frame_options(request, "DENY")
  if request.controller_instance.current_user.in_test_bucket?
    { child_src: %w(beta.thirdpartyhost.com) }
  else
    { child_src: %w(thirdpartyhost.com) }
  end
end
```

You can use as many named appends as you would like per request, but be careful because order of inclusion matters. Consider the following:

```ruby
SecureHeader::Configuration.default do |config|
  config.csp = { default_src: %w('self')}
end

SecureHeaders::Configuration.named_append(:A) do |request|
  { default_src: %w(myhost.com) }
end

SecureHeaders::Configuration.named_append(:B) do |request|
  { script_src: %w('unsafe-eval') }
end
```

The following code will produce different policies due to the way policies are normalized (e.g. providing a previously undefined directive that inherits from `default-src`, removing host source values when `*` is provided. Removing `'none'` when additional values are present, etc.):

```ruby
def index
  use_content_security_policy_named_append(:A)
  use_content_security_policy_named_append(:B)
  # produces default-src 'self' myhost.com; script-src 'self' myhost.com 'unsafe-eval';
end

def show
  use_content_security_policy_named_append(:B)
  use_content_security_policy_named_append(:A)
  # produces default-src 'self' myhost.com; script-src 'self' 'unsafe-eval';
end
```


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
    # Produces default-src 'self'; script-src example.org otherdomain.com
    use_secure_headers_override(:script_from_otherdomain_com)
  end

  def show
    # Produces default-src 'self'; script-src example.org otherdomain.org evenanotherdomain.com
    use_secure_headers_override(:another_config)
  end
end
```

By default, a no-op configuration is provided. No headers will be set when this default override is used.

```ruby
class MyController < ApplicationController
  def index
    SecureHeaders.opt_out_of_all_protection(request)
  end
end
```

## Per-action configuration

You can override the settings for a given action by producing a temporary override. Be aware that because of the dynamic nature of the value, the header values will be computed per request.

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
    # Produces: default-src 'self'; script-src 'self' s3.amazonaws.com; object-src 'self' www.youtube.com
    append_content_security_policy_directives(script_src: %w(s3.amazonaws.com), object_src: %w('self' www.youtube.com))

    # Overrides the previously set source list, override 'none' values
    # Produces: default-src 'self'; script-src s3.amazonaws.com; object-src 'self'
    override_content_security_policy_directives(script_src: %w(s3.amazonaws.com), object_src: %w('self'))

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

The value of `default_src` is joined with the addition if the it is a [fetch directive](https://w3c.github.io/webappsec-csp/#directives-fetch). Note the `https:` is carried over from the `default-src` config. If you do not want this, use `override_content_security_policy_directives` instead. To illustrate:

```ruby
::SecureHeaders::Configuration.default do |config|
   config.csp = {
     default_src: %w('self')
   }
 end
 ```

Code  | Result
------------- | -------------
`append_content_security_policy_directives(script_src: %w(mycdn.com))` | `default-src 'self'; script-src 'self' mycdn.com`
`override_content_security_policy_directives(script_src: %w(mycdn.com))`  | `default-src 'self'; script-src mycdn.com`

#### Nonce

You can use a view helper to automatically add nonces to script tags:

```erb
<%= nonced_javascript_tag do %>
console.log("nonced!");
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

```

Content-Security-Policy: ...
  script-src 'nonce-/jRAxuLJsDXAxqhNBB7gg7h55KETtDQBXe4ZL+xIXwI=' ...;
  style-src 'nonce-/jRAxuLJsDXAxqhNBB7gg7h55KETtDQBXe4ZL+xIXwI=' ...;
```

`script`/`style-nonce` can be used to whitelist inline content. To do this, call the `content_security_policy_script_nonce` or `content_security_policy_style_nonce` then set the nonce attributes on the various tags.

```erb
<script nonce="<%= content_security_policy_script_nonce %>">
  console.log("whitelisted, will execute")
</script>

<script nonce="lol">
  console.log("won't execute, not whitelisted")
</script>

<script>
  console.log("won't execute, not whitelisted")
</script>
```

#### Hash

`script`/`style-src` hashes can be used to whitelist inline content that is static. This has the benefit of allowing inline content without opening up the possibility of dynamic javascript like you would with a `nonce`.

You can add hash sources directly to your policy :

```ruby
::SecureHeaders::Configuration.default do |config|
   config.csp = {
     default_src: %w('self')

     # this is a made up value but browsers will show the expected hash in the console.
     script_src: %w(sha256-123456)
   }
 end
 ```

 You can also use the automated inline script detection/collection/computation of hash source values in your app.

 ```bash
 rake secure_headers:generate_hashes
 ```

 This will generate a file (`config/config/secure_headers_generated_hashes.yml` by default, you can override by setting `ENV["secure_headers_generated_hashes_file"]`) containing a mapping of file names with the array of hash values found on that page. When ActionView renders a given file, we check if there are any known hashes for that given file. If so, they are added as values to the header.

```yaml
---
scripts:
  app/views/asdfs/index.html.erb:
  - "'sha256-yktKiAsZWmc8WpOyhnmhQoDf9G2dAZvuBBC+V0LGQhg='"
styles:
  app/views/asdfs/index.html.erb:
  - "'sha256-SLp6LO3rrKDJwsG9uJUxZapb4Wp2Zhj6Bu3l+d9rnAY='"
  - "'sha256-HSGHqlRoKmHAGTAJ2Rq0piXX4CnEbOl1ArNd6ejp2TE='"
```

##### Helpers

**This will not compute dynamic hashes** by design. The output of both helpers will be a plain `script`/`style` tag without modification and the known hashes for a given file will be added to `script-src`/`style-src` when `hashed_javascript_tag` and `hashed_style_tag` are used. You can use `raise_error_on_unrecognized_hash = true` to be extra paranoid that you have precomputed hash values for all of your inline content. By default, this will raise an error in non-production environments.

```erb
<%= hashed_style_tag do %>
body {
  background-color: black;
}
<% end %>

<%= hashed_style_tag do %>
body {
  font-size: 30px;
  font-color: green;
}
<% end %>

<%= hashed_javascript_tag do %>
console.log(1)
<% end %>
```

```
Content-Security-Policy: ...
 script-src 'sha256-yktKiAsZWmc8WpOyhnmhQoDf9G2dAZvuBBC+V0LGQhg=' ... ;
 style-src 'sha256-SLp6LO3rrKDJwsG9uJUxZapb4Wp2Zhj6Bu3l+d9rnAY=' 'sha256-HSGHqlRoKmHAGTAJ2Rq0piXX4CnEbOl1ArNd6ejp2TE=' ...;
```

### Public Key Pins

Be aware that pinning error reporting is governed by the same rules as everything else. If you have a pinning failure that tries to report back to the same origin, by definition this will not work.

```ruby
config.hpkp = {
  max_age: 60.days.to_i,    # max_age is a required parameter
  include_subdomains: true, # whether or not to apply pins to subdomains
  # Per the spec, SHA256 hashes are the only currently supported format.
  pins: [
    {sha256: 'b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c'},
    {sha256: '73a2c64f9545172c1195efb6616ca5f7afd1df6f245407cafb90de3998a1c97f'}
  ],
  report_only: true,        # defaults to false (report-only mode)
  report_uri: 'https://report-uri.io/example-hpkp'
}
```

### Cookies

SecureHeaders supports `Secure`, `HttpOnly` and [`SameSite`](https://tools.ietf.org/html/draft-west-first-party-cookies-07) cookies. These can be defined in the form of a boolean, or as a Hash for more refined configuration.

__Note__: Regardless of the configuration specified, Secure cookies are only enabled for HTTPS requests.

#### Boolean-based configuration

Boolean-based configuration is intended to globally enable or disable a specific cookie attribute.

```ruby
config.cookies = {
  secure: true, # mark all cookies as Secure
  httponly: false, # do not mark any cookies as HttpOnly
}
```

#### Hash-based configuration

Hash-based configuration allows for fine-grained control.

```ruby
config.cookies = {
  secure: { except: ['_guest'] }, # mark all but the `_guest` cookie as Secure
  httponly: { only: ['_rails_session'] }, # only mark the `_rails_session` cookie as HttpOnly
}
```

#### SameSite cookie configuration

SameSite cookies permit either `Strict` or `Lax` enforcement mode options.

```ruby
config.cookies = {
  samesite: {
    strict: true # mark all cookies as SameSite=Strict
  }
}
```

`Strict` and `Lax` enforcement modes can also be specified using a Hash.

```ruby
config.cookies = {
  samesite: {
    strict: { only: ['_rails_session'] },
    lax: { only: ['_guest'] }
  }
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

SecureHeaders::Configuration.default do |config|
  ...
end

class Donkey < Sinatra::Application
  set :root, APP_ROOT

  get '/' do
    SecureHeaders.override_x_frame_options(request, SecureHeaders::OPT_OUT)
    haml :index
  end
end
```

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
