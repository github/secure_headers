## 1.0.0

* Drop support for ruby < 2.1.
* Support Pry 0.14
* Adding tests
* Fix warning on ruby 2.7

## 0.3.0 (2019-04-16)

* Fix circular require warning.
* Support Pry 0.11 & 0.12

## 0.2.4 (2014-06-25)

* Support Pry 0.10

## 0.2.3 (2012-12-26)

* Safer `alias_method_chain`-style patching of `Pry.start` and
  `PryRemote::Server#teardown`. (@benizi)

## 0.2.2 (2012-06-14)

* Upgrade to Pry 0.9.10. (@banister)

## 0.2.1 (2012-04-24)

* Upgrade to Pry 0.9.9. (@banister)
* Fix loading issues using new Pry cli.rb convention. No more explicit
  `require 'pry-nav'` should be necessary. (@banister)

## 0.2.0 (2012-02-19)

* Removed single letter aliases for **step**, **next**, and **continue** because
  of conflicts with common variable names.
* Update [pry-remote][pry-remote] support for 0.1.1. Older releases of
  pry-remote no longer supported.


## 0.1.0 (2012-02-02)

* MRI 1.8.7 support
* Upgrade to Pry 0.9.8


## 0.0.4 (2011-12-03)

* Performance improvement, primarily for 1.9.2: Don't trace unless in a file
  context. `rails console` or standard `pry` shouldn't experience a slowdown
  anymore.
* The overriden `Pry.start` now returns the output of the original method, not a
  `PryNav::Tracer` instance.
* For consistency with the other nav commands, **continue** now checks for a
  local file context.


## 0.0.3 (2011-12-01)

* Performance improvement: Don't trace while in the Pry console. Only works in
  >= 1.9.3-p0 because 1.9.2 segfaults: http://redmine.ruby-lang.org/issues/3921
* Always cleanup pry-remote DRb server and trace function when a program
  ends. Fixes [#1](https://github.com/nixme/pry-nav/issues/1).
* **step** and **next** now check for a local file context. Prevents errors and
  infinite loops when called from outside `binding.pry`, e.g. `rails console`.
* More resilient cleanup when [pry-remote][pry-remote] CLI disconnects.


## 0.0.2 (2011-11-30)

* Rudimentary [pry-remote][pry-remote] support. Still a bit buggy.
* **continue** command as an alias for **exit-all**


## 0.0.1 (2011-11-29)

* First release. Basic **step** and **next** commands.


[pry-remote]:  https://github.com/Mon-Ouie/pry-remote
