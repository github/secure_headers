### rails 2

For rails 3+ applications, `secure_headers` has a `railtie` that should automatically include the middleware. For rails 2 or non-rails applications, an explicit statement is required to use the middleware component.

```ruby
use SecureHeaders::Middleware
```

