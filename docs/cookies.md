## Cookies

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
