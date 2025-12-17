
module Growl
  
  BIN = 'growlnotify'
  
  #--
  # Exceptions
  #++
  
  class Error < StandardError; end
  
  ##
  # Display a growl notification +message+, with +options+ 
  # documented below. Alternatively a +block+ may be passed
  # which is then instance evaluated or yielded to the block.
  #
  # This method is simply returns nil when growlnotify
  # is not installed, as growl notifications should never
  # be the only means of communication between your application
  # and your user.
  #
  # === Examples
  #    
  #   Growl.notify 'Hello'
  #   Growl.notify 'Hello', :title => 'TJ Says:', :sticky => true
  #   Growl.notify { |n| n.message = 'Hello'; n.sticky! }
  #   Growl.notify { self.message = 'Hello'; sticky! }
  #
  
  def notify message = nil, options = {}, &block
    return unless Growl.installed?
    options.merge! :message => message if message
    Growl.normalize_icon! options
    Growl.new(options, &block).run
  end
  module_function :notify
  
  #--
  # Generate notify_STATUS methods.
  #++
  
  %w( ok info warning error ).each do |type|
    define_method :"notify_#{type}" do |message, *args|
      options = args.first || {}
      image = File.join File.expand_path(File.dirname(__FILE__)), 'images', "#{type}.png"
      notify message, options.merge(:image => image)
    end
    module_function :"notify_#{type}"
  end
  
  ##
  # Execute +args+ against the binary.
  
  def self.exec *args
    Kernel.system BIN, *args
  end
  
  ##
  # Return the version triple of the binary.
  
  def self.version
    @version ||= `#{BIN} --version`.split[1]
  end
  
  ##
  # Check if the binary is installed and accessable.
  
  def self.installed?
    version rescue false
  end
  
  ##
  # Return an instance of Growl::Base or nil when not installed.
  
  def self.new *args, &block
    return unless installed?
    Base.new *args, &block
  end
  
  ##
  # Normalize the icon option in +options+. This performs
  # the following operations in order to allow for the :icon
  # key to work with a variety of values:
  #
  # * path to an icon sets :iconpath
  # * path to an image sets :image
  # * capitalized word sets :appIcon
  # * filename uses extname as :icon
  # * otherwise treated as :icon
  
  def self.normalize_icon! options = {}
    return unless options.include? :icon
    icon = options.delete(:icon).to_s
    if File.exists? icon
      if File.extname(icon) == '.icns'
        options[:iconpath] = icon
      else
        options[:image] = icon
      end
    else
      if icon.capitalize == icon
        options[:appIcon] = icon
      elsif !(ext = File.extname(icon)).empty?
        options[:icon] = ext[1..-1]
      else
        options[:icon] = icon
      end
    end
  end
  
  #--
  # Growl base
  #++
  
  class Base
    attr_reader :args
    
    ##
    # Initialize with optional +block+, which is then
    # instance evaled or yielded depending on the blocks arity.
    
    def initialize options = {}, &block
      @args = []
      if block_given?
        if block.arity > 0
          yield self
        else
          self.instance_eval &block
        end
      else
        options.each do |key, value|
          send :"#{key}=", value
        end
      end
    end
    
    ##
    # Run the notification, only --message is required.
    
    def run
      raise Error, 'message required' unless message
      self.class.switches.each do |switch|
        if send(:"#{switch}?")
          args << "--#{switch}"
          args << send(switch).to_s if send(switch) && !(TrueClass === send(switch))
        end
      end
      Growl.exec *args
    end
    
    ##
    # Define a switch +name+.
    #
    # === examples
    #
    #  switch :sticky
    #
    #  @growl.sticky!         # => true
    #  @growl.sticky?         # => true
    #  @growl.sticky = false  # => false
    #  @growl.sticky?         # => false
    #
    
    def self.switch name
      ivar = :"@#{name}"
      (@switches ||= []) << name
      attr_accessor :"#{name}"
      define_method(:"#{name}?") { instance_variable_get(ivar) }
      define_method(:"#{name}!") { instance_variable_set(ivar, true) }
    end
    
    ##
    # Return array of available switch symbols.
    
    def self.switches
      @switches
    end
    
    #--
    # Switches
    #++
    
    switch :title
    switch :message
    switch :sticky
    switch :name
    switch :appIcon
    switch :icon
    switch :iconpath
    switch :image
    switch :priority
    switch :identifier
    switch :host
    switch :password
    switch :udp
    switch :port
    switch :auth
    switch :crypt

  end

end