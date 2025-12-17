module TerminalNotifier
  module Guard
    VERSION = "1.7.0"
    ICONS_PATH = File.expand_path("../../icons", __FILE__)
    GUARD_ICON = File.join(ICONS_PATH, 'Guard.icns')

    def self.osx_version
      Gem::Version.new(`sw_vers -productVersion`.strip)
    end

    def self.terminal_notifier_version
      return Gem::Version("0.0.0") unless installed?
      # invoke the help option since the binary otherwise may get stuck
      Gem::Version.new(`#{bin_path} -help`.lines.first.match(/\d\.\d\.\d/)[0])
    rescue
      Gem::Version.new("0.0.0")
    end

    def self.deprecation_check
      if osx_version <= Gem::Version.new('10.8')
        raise "OSX 10.8 is no longer supported by this gem. Please revert to version <= 1.5.3."
      end

      if terminal_notifier_version < Gem::Version.new('1.6.0')
        puts "Notice: Your terminal-notifier is older than what terminal-notifier-guard supports, consider upgrading."
      end
    end

    # Returns wether or not the current platform is Mac OS X 10.8, or higher.
    def self.available?
      deprecation_check
      if @available.nil?
        @available = `uname`.strip == 'Darwin' &&
          osx_version >= Gem::Version.new('10.9')
      end
      @available
    end

    # Whether or not the terminal notifier is installed
    def self.installed?
      File.exist? bin_path
    end

    def self.bin_path
      ENV["TERMINAL_NOTIFIER_BIN"] || begin
        @@binary ||= `which terminal-notifier`.chomp
      end
    end

    def self.execute(verbose, options)
      if available? && installed?
        options.merge!({ :contentImage=> GUARD_ICON, :appIcon => icon(options.delete(:type)) })

        command = [bin_path, *options.map { |k,v| ["-#{k}", v.to_s] }.flatten]
        if RUBY_VERSION < '1.9'
          require 'shellwords'
          command = Shellwords.shelljoin(command)
        end
        result = ''
        IO.popen(command) do |stdout|
          output = stdout.read
          STDOUT.print output if verbose
          result << output
        end
        result
      else
        raise "terminal-notifier is only supported on Mac OS X 10.8, or higher." if !available?
        raise "TerminalNotifier not installed. Please do so by running `brew install terminal-notifier`" if !installed?
      end
    end

    # Sends a User Notification and returns wether or not it was a success.
    #
    # The available options are `:title`, `:group`, `:activate`, `:open`, and
    # `:execute`. For a description of each option see:
    #
    #   https://github.com/alloy/terminal-notifier/blob/master/README.markdown
    #
    # Examples are:
    #
    #   TerminalNotifier::Guard.notify('Hello World')
    #   TerminalNotifier::Guard.notify('Hello World', :title => 'Ruby')
    #   TerminalNotifier::Guard.notify('Hello World', :group => Process.pid)
    #   TerminalNotifier::Guard.notify('Hello World', :activate => 'com.apple.Safari')
    #   TerminalNotifier::Guard.notify('Hello World', :open => 'http://twitter.com/alloy')
    #   TerminalNotifier::Guard.notify('Hello World', :execute => 'say "OMG"')
    #
    # Raises if not supported on the current platform.
    def notify(message, options = {}, verbose = false)
      TerminalNotifier::Guard.execute(verbose, options.merge(:message => message))
      $?.success?
    end
    module_function :notify

    def failed(message, options = {}, verbose = false)
      TerminalNotifier::Guard.execute(verbose, options.merge(:message => message, :type => :failed))
      $?.success?
    end
    module_function :failed

    def pending(message, options = {}, verbose = false)
      TerminalNotifier::Guard.execute(verbose, options.merge(:message => message, :type => :pending))
      $?.success?
    end
    module_function :pending

    def success(message, options = {}, verbose = false)
      TerminalNotifier::Guard.execute(verbose, options.merge(:message => message, :type => :success))
      $?.success?
    end
    module_function :success

    def icon(type = :notify)
      type ||= :notify
      file_name = "#{type}.icns".capitalize
      File.join(ICONS_PATH, file_name)
    end
    module_function :icon

    # Removes a notification that was previously sent with the specified
    # ‘group’ ID, if one exists.
    #
    # If no ‘group’ ID is given, all notifications are removed.
    def remove(group = 'ALL', verbose = false)
      TerminalNotifier::Guard.execute(verbose, :remove => group)
      $?.success?
    end
    module_function :remove

    LIST_FIELDS = [:group, :title, :subtitle, :message, :delivered_at].freeze

    # If a ‘group’ ID is given, and a notification for that group exists,
    # returns a hash with details about the notification.
    #
    # If no ‘group’ ID is given, an array of hashes describing all
    # notifications.
    #
    # If no information is available this will return `nil`.
    def list(group = 'ALL', verbose = false)
      output = TerminalNotifier::Guard.execute(verbose, :list => group)
      return if output.strip.empty?

      require 'time'
      notifications = output.split("\n")[1..-1].map do |line|
        LIST_FIELDS.zip(line.split("\t")).inject({}) do |hash, (key, value)|
          hash[key] = key == :delivered_at ? Time.parse(value) : (value unless value == '(null)')
          hash
        end
      end

      group == 'ALL' ? notifications : notifications.first
    end
    module_function :list
  end
end
