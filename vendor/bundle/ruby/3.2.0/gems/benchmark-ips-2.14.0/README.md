# benchmark-ips

* rdoc :: http://rubydoc.info/gems/benchmark-ips
* home :: https://github.com/evanphx/benchmark-ips

[![Gem Version](https://badge.fury.io/rb/benchmark-ips.svg)](http://badge.fury.io/rb/benchmark-ips)
[![Build Status](https://secure.travis-ci.org/evanphx/benchmark-ips.svg)](http://travis-ci.org/evanphx/benchmark-ips)
[![Inline docs](http://inch-ci.org/github/evanphx/benchmark-ips.svg)](http://inch-ci.org/github/evanphx/benchmark-ips)

* https://github.com/evanphx/benchmark-ips

## DESCRIPTION:

An iterations per second enhancement to Benchmark.

## FEATURES/PROBLEMS:

 * benchmark/ips - benchmarks a blocks iterations/second. For short snippits
   of code, ips automatically figures out how many times to run the code
   to get interesting data. No more guessing at random iteration counts!

## SYNOPSIS:

```ruby
require 'benchmark/ips'

Benchmark.ips do |x|
  # Configure the number of seconds used during
  # the warmup phase (default 2) and calculation phase (default 5)
  x.config(warmup: 2, time: 5)

  # Typical mode, runs the block as many times as it can
  x.report("addition") { 1 + 2 }

  # To reduce overhead, the number of iterations is passed in
  # and the block must run the code the specific number of times.
  # Used for when the workload is very small and any overhead
  # introduces incorrectable errors.
  x.report("addition2") do |times|
    i = 0
    while i < times
      i += 1

      1 + 2
    end
  end

  # To reduce overhead even more, grafts the code given into
  # the loop that performs the iterations internally to reduce
  # overhead. Typically not needed, use the |times| form instead.
  x.report("addition3", "1 + 2")

  # Really long labels should be formatted correctly
  x.report("addition-test-long-label") { 1 + 2 }

  # Compare the iterations per second of the various reports!
  x.compare!
end
```

This will generate the following report:

```
Warming up --------------------------------------
            addition     3.572M i/100ms
           addition2     3.672M i/100ms
           addition3     3.677M i/100ms
addition-test-long-label
                         3.511M i/100ms
Calculating -------------------------------------
            addition     36.209M (± 2.8%) i/s   (27.62 ns/i) -    182.253M in   5.037433s
           addition2     36.552M (± 7.8%) i/s   (27.36 ns/i) -    183.541M in   5.069987s
           addition3     36.639M (± 4.8%) i/s   (27.29 ns/i) -    182.994M in   5.009234s
addition-test-long-label
                         36.164M (± 5.8%) i/s   (27.65 ns/i) -    181.312M in   5.038364s

Comparison:
           addition2: 36558904.5 i/s
           addition3: 36359284.0 i/s - same-ish: difference falls within error
addition-test-long-label: 36135428.8 i/s - same-ish: difference falls within error
            addition: 34666931.3 i/s - same-ish: difference falls within error
```

Benchmark/ips will report the number of iterations per second for a given block
of code. When analyzing the results, notice the percent of [standard
deviation](http://en.wikipedia.org/wiki/Standard\_deviation) which tells us how
spread out our measurements are from the average. A high standard deviation
could indicate the results having too much variability.

One benefit to using this method is benchmark-ips automatically determines the
data points for testing our code, so we can focus on the results instead of
guessing iteration counts as we do with the traditional Benchmark library.

You can also use `ips_quick` to save a few lines of code:

```ruby
Benchmark.ips_quick(:upcase, :downcase, on: "hello") # runs a suite comparing "hello".upcase and "hello".downcase

def first; MyJob.perform(1); end
def second; MyJobOptimized.perform(1); end
Benchmark.ips_quick(:first, :second) # compares :first and :second
```

This adds a very small amount of overhead, which may be significant (i.e. ips_quick will understate the difference) if you're microbenchmarking things that can do over 1 million iterations per second. In that case, you're better off using the full format.

### Custom Suite

Pass a custom suite to disable garbage collection during benchmark:

```ruby
require 'benchmark/ips'

# Enable and start GC before each job run. Disable GC afterwards.
#
# Inspired by https://www.omniref.com/ruby/2.2.1/symbols/Benchmark/bm?#annotation=4095926&line=182
class GCSuite
  def warming(*)
    run_gc
  end

  def running(*)
    run_gc
  end

  def warmup_stats(*)
  end

  def add_report(*)
  end

  private

  def run_gc
    GC.enable
    GC.start
    GC.disable
  end
end

suite = GCSuite.new

Benchmark.ips do |x|
  x.config(:suite => suite)
  x.report("job1") { ... }
  x.report("job2") { ... }
end
```

### Independent benchmarking

If you are comparing multiple implementations of a piece of code you may want
to benchmark them in separate invocations of Ruby so that the measurements
are independent of each other. You can do this with the `hold!` command.

```ruby
Benchmark.ips do |x|

  # Hold results between multiple invocations of Ruby
  x.hold! 'filename'

end
```

This will run only one benchmarks each time you run the command, storing
results in the specified file. The file is deleted when all results have been
gathered and the report is shown.

Alternatively, if you prefer a different approach, the `save!` command is
available. Examples for [hold!](examples/hold.rb) and [save!](examples/save.rb) are available in
the `examples/` directory.


### Multiple iterations

In some cases you may want to run multiple iterations of the warmup and
calculation stages and take only the last result for comparison. This is useful
if you are benchmarking with an implementation of Ruby that optimizes using
tracing or on-stack-replacement, because to those implementations the
calculation phase may appear as new, unoptimized code.

You can do this with the `iterations` option, which by default is `1`. The
total time spent will then be `iterations * warmup + iterations * time` seconds.

```ruby
Benchmark.ips do |x|

  x.config(:iterations => 3)

    # or

  x.iterations = 3

end
```

### Online sharing

If you want to quickly share your benchmark result with others, run you benchmark
with `SHARE=1` argument. For example: `SHARE=1 ruby my_benchmark.rb`.

Result will be sent to [benchmark.fyi](https://ips.fastruby.io/) and benchmark-ips
will display the link to share the benchmark's result.

If you want to run your own instance of [benchmark.fyi](https://github.com/evanphx/benchmark.fyi)
and share it to that instance, you can do this: `SHARE_URL=https://ips.example.com ruby my_benchmark.rb`

### Advanced Statistics

By default, the margin of error shown is plus-minus one standard deviation. If
a more advanced statistical test is wanted, a bootstrap confidence interval
can be calculated instead. A bootstrap confidence interval has the advantages of
arguably being more mathematically sound for this application than a standard
deviation, it additionally produces an error for relative slowdowns, which the
standard deviation does not, and it is arguably more intuitive and actionable.

When a bootstrap confidence interval is used, a median of the interval is used
rather than the mean of the samples, which is what you get with the default
standard deviation.

The bootstrap confidence interval used is the one described by Tomas Kalibera.
Note that for this technique to be valid your benchmark should have reached a
non-periodic steady state with statistically independent samples (it should
have warmed up) by the time measurements start.

Using a bootstrap confidence internal requires that the 'kalibera' gem is
installed separately. This gem is not a formal dependency, as by default it is
not needed.

```
gem install kalibera
```

```ruby
Benchmark.ips do |x|

  # The default is :stats => :sd, which doesn't have a configurable confidence
  x.config(:stats => :bootstrap, :confidence => 95)

    # or

  x.stats = :bootstrap
  x.confidence = 95

  # confidence is 95% by default, so it can be omitted

end
```

### Output as JSON

You can generate output in JSON. If you want to write JSON to a file, pass filename to `json!` method:

```ruby
Benchmark.ips do |x|
  x.report("some report") {  }
  x.json! 'filename.json'
end
```

If you want to write JSON to STDOUT, pass `STDOUT` to `json!` method and set `quiet = true` before `json!`:

```ruby
Benchmark.ips do |x|
  x.report("some report") {  }
  x.quiet = true
  x.json! STDOUT
end
```

This is useful when the output from `benchmark-ips` becomes an input of other tools via stdin.

## REQUIREMENTS:

* None!

## INSTALL:

    $ gem install benchmark-ips

## DEVELOPERS:

After checking out the source, run:

    $ rake newb

This task will install any missing dependencies, run the tests/specs,
and generate the RDoc.

