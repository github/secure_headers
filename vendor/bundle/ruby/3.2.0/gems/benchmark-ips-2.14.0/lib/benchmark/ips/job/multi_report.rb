module Benchmark
  module IPS
    class Job
      class MultiReport
        # @returns out [Array<StreamReport>] list of reports to send output
        attr_accessor :out

        def empty?
          @out.empty?
        end

        def quiet?
          @out.none? { |rpt| rpt.kind_of?(StreamReport) }
        end

        def quiet!
          @out.delete_if { |rpt| rpt.kind_of?(StreamReport) }
        end

        # @param report [StreamReport] report to accept input?
        def <<(report)
          if report.kind_of?(MultiReport)
            self << report.out
          elsif report.kind_of?(Enumerable)
            @out += report
          elsif report
            @out << report
          end
        end

        # @param out [Array<StreamReport>] list of reports to send output
        def initialize(out = nil)
          @out = []
          self << out
        end

        def start_warming
          @out.each { |o| o.start_warming if o.respond_to?(:start_warming) }
        end

        def warming(label, warmup)
          @out.each { |o| o.warming(label, warmup) }
        end

        def warmup_stats(warmup_time_us, timing)
          @out.each { |o| o.warmup_stats(warmup_time_us, timing) }
        end

        def start_running
          @out.each { |o| o.start_running if o.respond_to?(:start_running) }
        end

        def running(label, warmup)
          @out.each { |o| o.running(label, warmup) }
        end

        def add_report(item, caller)
          @out.each { |o| o.add_report(item, caller) }
        end

        def footer
          @out.each { |o| o.footer if o.respond_to?(:footer) }
        end
      end
    end
  end
end
