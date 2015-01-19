# SecureHeaders [![Build Status](https://travis-ci.org/twitter/secureheaders.png?branch=master)](http://travis-ci.org/twitter/secureheaders) [![Code Climate](https://codeclimate.com/github/twitter/secureheaders.png)](https://codeclimate.com/github/twitter/secureheaders) [![Coverage Status](https://coveralls.io/repos/twitter/secureheaders/badge.png)](https://coveralls.io/r/twitter/secureheaders)

The gem will automatically apply several headers that are related to security.  This includes:
- Content Security Policy (CSP) - Helps detect/prevent XSS, mixed-content, and other classes of attack.  [CSP 1.1 Specification](https://dvcs.w3.org/hg/content-security-policy/raw-file/tip/csp-specification.dev.html)
- HTTP Strict Transport Security (HSTS) - Ensures the browser never visits the http version of a website. Protects from SSLStrip/Firesheep attacks.  [HSTS Specification](https://tools.ietf.org/html/rfc6797)
- X-Frame-Options (XFO) - Prevents your content from being framed and potentially clickjacked. [X-Frame-Options draft](https://tools.ietf.org/html/draft-ietf-websec-x-frame-options-02)
- X-XSS-Protection - [Cross site scripting heuristic filter for IE/Chrome](http://msdn.microsoft.com/en-us/library/dd565647\(v=vs.85\).aspx)
- X-Content-Type-Options - [Prevent content type sniffing](http://msdn.microsoft.com/en-us/library/ie/gg622941\(v=vs.85\).aspx)
- X-Download-Options - [Prevent file downloads opening](http://msdn.microsoft.com/en-us/library/ie/jj542450(v=vs.85).aspx)
- X-Permitted-Cross-Domain-Policies - [Restrict Adobe Flash Player's access to data](https://www.adobe.com/devnet/adobe-media-server/articles/cross-domain-xml-for-streaming.html)
- Public Key Pinning - Pin certificate fingerprints in the browser to prevent man-in-the-middle attacks due to compromised Certificate Authorites. [Public Key Pinnning  Specification](https://tools.ietf.org/html/draft-ietf-websec-key-pinning-21)

## Usage

- `ensure_security_headers` in a controller will set security-related headers automatically based on the configuration below.

### Disabling

Use the standard `skip_before_filter :filter_name, options` mechanism. e.g. `skip_before_filter :set_csp_header, :only => :tinymce_page`

The following methods are going to be called, unless they are provided in a `skip_before_filter` block.

* `:set_csp_header`
* `:set_hsts_header`
* `:set_hpkp_header`
* `:set_x_frame_options_header`
* `:set_x_xss_protection_header`
* `:set_x_content_type_options_header`
* `:set_x_download_options_header`
* `:set_x_permitted_cross_domain_policies_header`

### Bonus Features

This gem makes a few assumptions about how you will use some features.  For example:

* It fills any blank directives with the value in `:default_src`  Getting a default\-src report is pretty useless.  This way, you will always know what type of violation occurred. You can disable this feature by supplying `:disable_fill_missing => true`. This is referred to as the "effective-directive" in the spec, but is not well supported as of Nov 5, 2013.

## Configuration

**Place the following in an initializer (recommended):**

```ruby
::SecureHeaders::Configuration.configure do |config|
  config.hsts = {:max_age => 20.years.to_i, :include_subdomains => true}
  config.x_frame_options = 'DENY'
  config.x_content_type_options = "nosniff"
  config.x_xss_protection = {:value => 1, :mode => 'block'}
  config.x_download_options = 'noopen'
  config.x_permitted_cross_domain_policies = 'none'
  config.csp = {
    :default_src => "https: self",
    :frame_src => "https: http:.twimg.com http://itunes.apple.com",
    :img_src => "https:",
    :report_uri => '//example.com/uri-directive'
  }
  config.hpkp = {
    :max_age => 60.days.to_i,
    :include_subdomains => true,
    :report_uri => '//example.com/uri-directive',
    :pins => [{:sha256 => 'b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c'}]
  }
end

# and then simply include this in application_controller.rb
class ApplicationController < ActionController::Base
  ensure_security_headers
end
```

Or simply add it to application controller

```ruby
ensure_security_headers(
  :hsts => {:include_subdomains => true, :max_age => 20.years.to_i},
  :x_frame_options => 'DENY',
  :csp => false
)
```

## Options for ensure\_security\_headers

**To disable any of these headers, supply a value of false (e.g. :hsts => false), supplying nil will set the default value**

Each header configuration can take a hash, or a string, or both. If a string
is provided, that value is inserted verbatim.  If a hash is supplied, a
header will be constructed using the supplied options.

### The Easy Headers

This configuration will likely work for most applications without modification.

```ruby
:hsts             => {:max_age => 631138519, :include_subdomains => false}
:x_frame_options  => {:value => 'SAMEORIGIN'}
:x_xss_protection => {:value => 1, :mode => 'block'}  # set the :mode option to false to use "warning only" mode
:x_content_type_options => {:value => 'nosniff'}
:x_download_options => {:value => 'noopen'}
:x_permitted_cross_domain_policies => {:value => 'none'}
```

### Content Security Policy (CSP)

```ruby
:csp => {
  :enforce     => false,        # sets header to report-only, by default
  # default_src is required!
  :default_src     => nil,      # sets the default-src/allow+options directives

  # Where reports are sent. Use protocol relative URLs if you are posting to the same domain (TLD+1). Use paths if you are posting to the application serving the header
  :report_uri  => '//mysite.example.com',

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
  #   :img_src => 'https:',
  #   :http_additions => {:img_src => 'http'}
  # }
  # would produce the directive: "img-src https: http:;"
  # when over http, ignored for https requests
  :http_additions => {}
}
```

### Example CSP header config


```ruby
# most basic example
:csp => {
  :default_src => "https: inline eval",
  :report_uri => '/uri-directive'
}

> "default-src 'unsafe-inline' 'unsafe-eval' https:; report-uri /uri-directive;"

# turn off inline scripting/eval
:csp => {
  :default_src => 'https:',
  :report_uri => '/uri-directive'
}

> "default-src  https:; report-uri /uri-directive;"

# Auction site wants to allow images from anywhere, plugin content from a list of trusted media providers (including a content distribution network), and scripts only from its server hosting sanitized JavaScript
:csp => {
  :default_src => 'self',
  :img_src => '*',
  :object_src => ['media1.com', 'media2.com', '*.cdn.com'],
  # alternatively (NOT csv) :object_src => 'media1.com media2.com *.cdn.com'
  :script_src => 'trustedscripts.example.com'
}
"default-src  'self'; img-src *; object-src media1.com media2.com *.cdn.com; script-src trustedscripts.example.com;"
```

### Tagging Requests

It's often valuable to send extra information in the report uri that is not available in the reports themselves. Namely, "was the policy enforced" and "where did the report come from"

```ruby
{
  :tag_report_uri => true,
  :enforce => true,
  :app_name => 'twitter',
  :report_uri => 'csp_reports'
}
```

Results in
```
report-uri csp_reports?enforce=true&app_name=twitter
```

### CSP Level 2 features

*NOTE: Currently, only erb is supported. Mustache support isn't far off. Hash sources are valid for inline style blocks but are not yet supported by secure_headers.*

#### Nonce

script/style-nonce can be used to whitelist inline content. To do this, add "nonce" to your script/style-src configuration, then set the nonce attributes on the various tags.

Setting a nonce will also set 'unsafe-inline' for browsers that don't support nonces for backwards compatibility. 'unsafe-inline' is ignored if a nonce is present in a directive in compliant browsers.

```ruby
:csp => {
  :default_src => 'self',
  :script_src => 'self nonce'
}
```

> content-security-policy: default-src 'self'; script-src 'self' 'nonce-abc123' 'unsafe-inline'

```erb
<script nonce="<%= @content_security_policy_nonce %>">
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

setting hash source values will also set 'unsafe-inline' for browsers that don't support hash sources for backwards compatibility. 'unsafe-inline' is ignored if a hash is present in a directive in compliant browsers.

Hash source support works by taking the hash value of the contents of an inline script block and adding the hash "fingerprint" to the CSP header.

If you only have a few hashes, you can hardcode them for the entire app:

```ruby
  config.csp = {
    :default_src => "https:",
    :script_src => 'self'
    :script_hashes => ['sha1-abc', 'sha1-qwe']
  }
```

The following will work as well, but may not be as clear:

```ruby
  config.csp = {
    :default_src => "https:",
    :script_src => "self 'sha1-qwe'"
  }
```

If you find you have many hashes or the content of the script tags change frequently, you can apply these hashes in a more intelligent way. This method expects config/script_hashes.yml to contain a map of templates => [hashes]. When the individual templates, layouts, or partials are rendered the hash values for the script tags in those templates will be automatically added to the header. *Currently, only erb layouts are supported.* This requires the use of middleware:

```ruby
# config.ru
require 'secure_headers/headers/content_security_policy/script_hash_middleware'
use ::SecureHeaders::ContentSecurityPolicy::ScriptHashMiddleware
```

```ruby
  config.csp = {
    :default_src => "https:",
    :script_src => 'self',
    :script_hash_middleware => true
  }
```

Hashes are stored in a yaml file with a mapping of Filename => [list of hashes] in config/script_hashes.yml. You can automatically populate this file by running the following rake task:

```$ bundle exec rake secure_headers:generate_hashes```

Which will generate something like:

```yaml
# config/script_hashes.yml
app/views/layouts/application.html.erb:
- sha256-l8OLjZqYRnKilpdE0VosRMvhdYArjXT4NZaK2p7QVvs=
app/templates/articles/edit.html.erb:
- sha256-+7mij1/uCwtCQRWrof2NmOln5qX+5WdVwTLMpi8nuoA=
- sha256-Ny4TRIhhFpnYnSeKC274P6bfAz4TOkezLabavIAU4dA=
- sha256-I5e58Gqbu4WpO9dck18QxO7aYOHKrELIi70it4jIPi0=
- sha256-Po4LMynwnAJHxiTp3DQaQ3YDBj3paN/xrDoKl4OyxY4=
```

In this example, if we visit /articles/edit/[id], the above hashes will automatically be added to the CSP header's
script-src value!

You can use plain "script" tags or you can use a built-in helper:

```erb
<%= hashed_javascript_tag do %>
console.log("hashed automatically!")
<% end %>
```

By using the helper, hash values will be computed dynamically in development/test environments. If a dynamically computed hash value does not match what is expected to be found in config/script_hashes.yml a warning message will be printed to the console. If you want to raise exceptions instead, use:

```erb
<%= hashed_javascript_tag(raise_error_on_unrecognized_hash = true) do %>
console.log("will raise an exception if not in script_hashes.yml!")
<% end %>
```

### Public Key Pins

```
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

::SecureHeaders::Configuration.configure do |config|
  config.hsts = {:max_age => 99, :include_subdomains => true}
  config.x_frame_options = 'DENY'
  config.x_content_type_options = "nosniff"
  config.x_xss_protection = {:value => 1, :mode => false}
  config.x_download_options = 'noopen'
  config.x_permitted_cross_domain_policies = 'none'
  config.csp = {
    :default_src => "https: inline eval",
    :report_uri => '//example.com/uri-directive',
    :img_src => "https: data:",
    :frame_src => "https: http:.twimg.com http://itunes.apple.com"
  }
  config.hpkp = false
end

class Donkey < Sinatra::Application
  include SecureHeaders
  set :root, APP_ROOT

  get '/' do
    set_csp_header
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
require 'secure_headers/padrino'

module Web
  class App < Padrino::Application
    register SecureHeaders::Padrino

    get '/' do
      set_csp_header
      render 'index'
    end
  end
end
```

and in `config/boot.rb`:

```ruby
def before_load
  ::SecureHeaders::Configuration.configure do |config|
    config.hsts                   = {:max_age => 99, :include_subdomains => true}
    config.x_frame_options        = 'DENY'
    config.x_content_type_options = "nosniff"
    config.x_xss_protection       = {:value   => '1', :mode => false}
    config.x_download_options     = 'noopen'
    config.x_permitted_cross_domain_policies = 'none'
    config.csp                    = {
      :default_src => "https: inline eval",
      :report_uri => '//example.com/uri-directive',
      :img_src => "https: data:",
      :frame_src => "https: http:.twimg.com http://itunes.apple.com"
    }
  end
end
```

## Similar libraries

* Node.js (express) [helmet](https://github.com/evilpacket/helmet) and [hood](https://github.com/seanmonstar/hood)
* J2EE Servlet >= 3.0 [highlines](https://github.com/sourceclear/headlines)
* ASP.NET - [NWebsec](http://nwebsec.codeplex.com/)
* Python - [django-csp](https://github.com/mozilla/django-csp/) + [commonware](https://github.com/jsocol/commonware/)
* Go - [secureheader](https://github.com/kr/secureheader)

## Authors

* Neil Matatall [@ndm](https://twitter.com/ndm) - primary author.
* Nicholas Green [@nickgreen](https://twitter.com/nickgreen) - code contributions, main reviewer.

## Acknowledgements

* Justin Collins [@presidentbeef](https://twitter.com/presidentbeef) & Jim O'Leary [@jimio](https://twitter.com/jimio) for reviews.
* Ian Melven [@imelven](https://twitter.com/imelven) - Discussions/info about CSP in general, made us aware of the [userCSP](https://addons.mozilla.org/en-US/firefox/addon/newusercspdesign/) Mozilla extension.
* Sumit Shah [@omnidactyl](https://twitter.com/omnidactyl) - For being an eager guinea pig.
* Chris Aniszczyk [@cra](https://twitter.com/cra) - For running an awesome open source program at Twitter.

## License

Copyright 2013-2014 Twitter, Inc and other contributors.

Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0
