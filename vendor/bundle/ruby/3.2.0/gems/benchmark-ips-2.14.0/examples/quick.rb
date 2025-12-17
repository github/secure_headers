#!/usr/bin/env ruby

require 'benchmark/ips'

def add
  1 + 1
end

def sub
  2 - 1
end

Benchmark.ips_quick(:add, :sub, warmup: 1, time: 1)

h = {}

Benchmark.ips_quick(:size, :empty?, on: h)