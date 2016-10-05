## Getting Started

Add the gem to your `Gemfile` and `bundle install`.

```
gem 'secure_headers'
```

## Rails

### Rails 3+

For Rails 3+ applications, `secure_headers` has a `railtie` that should automatically include the middleware.

### Rails 2

For Rails 2 or non-rails applications, an explicit statement is required to use the middleware component.

```ruby
use SecureHeaders::Middleware
```


## Sinatra

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
