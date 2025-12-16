### Using MRI? We recommend [**break**][break] or [**pry-byebug**][pry-byebug] instead!

# pry-nav [![Ruby](https://github.com/nixme/pry-nav/actions/workflows/main.yml/badge.svg)](https://github.com/nixme/pry-nav/actions/workflows/main.yml)

_A simple execution control add-on for [Pry][pry]._

Compatible with MRI >= 2.1.0, JRuby >= 9.1.3.0.

Teaches [Pry][pry] about `step`, `next`, and `continue` to create a simple
debugger.

To use, invoke `pry` normally:

```ruby
def some_method
  binding.pry          # Execution will stop here.
  puts 'Hello, World!' # Run 'step' or 'next' in the console to move here.
end
```

When using JRuby, you also need to run it with the `--debug` flag. You can
also add the flag to your `JRUBY_OPTS` environment variable for it to apply
when running any ruby command, but do note that even when not making use of
`pry` this has a big impact on JRuby performance.

`pry-nav` is not yet thread-safe, so only use in single-threaded environments.

Rudimentary support for [`pry-remote`][pry-remote] (>= 0.1.1) is also included.
Ensure `pry-remote` is loaded or required before `pry-nav`. For example, in a
`Gemfile`:

```ruby
gem 'pry'
gem 'pry-remote'
gem 'pry-nav'
```

Stepping through code often? Add the following shortcuts to `~/.pryrc`:

```ruby
Pry.commands.alias_command 'c', 'continue'
Pry.commands.alias_command 's', 'step'
Pry.commands.alias_command 'n', 'next'
```

Please note that debugging functionality is implemented through
[`set_trace_func`][set_trace_func], which imposes a large performance
penalty.

## Contributors

* Gopal Patel ([@nixme](https://github.com/nixme))
* John Mair ([@banister](https://github.com/banister))
* Conrad Irwin ([@ConradIrwin](https://github.com/ConradIrwin))
* Benjamin R. Haskell ([@benizi](https://github.com/benizi))
* Jason R. Clark ([@jasonrclark](https://github.com/jasonrclark))
* Ivo Anjo ([@ivoanjo](https://github.com/ivoanjo))
* Michael Bianco ([@iloveitaly](https://github.com/iloveitaly))

Patches and bug reports are welcome. Just send a [pull request][pullrequests] or
file an [issue][issues]. [Project changelog][changelog].

## Acknowledgments

* Ruby stdlib's [debug.rb][debug.rb]
* [@Mon-Ouie][Mon-Ouie]'s [pry_debug][pry_debug]

[pry]:            http://pryrepl.org/
[pry-remote]:     https://github.com/Mon-Ouie/pry-remote
[set_trace_func]: http://www.ruby-doc.org/core-1.9.3/Kernel.html#method-i-set_trace_func
[pullrequests]:   https://github.com/nixme/pry-nav/pulls
[issues]:         https://github.com/nixme/pry-nav/issues
[changelog]:      https://github.com/nixme/pry-nav/blob/master/CHANGELOG.md
[debug.rb]:       https://github.com/ruby/ruby/blob/trunk/lib/debug.rb
[Mon-Ouie]:       https://github.com/Mon-Ouie
[pry_debug]:      https://github.com/Mon-Ouie/pry_debug
[pry-byebug]:     https://github.com/deivid-rodriguez/pry-byebug
[break]:          https://github.com/gsamokovarov/break
