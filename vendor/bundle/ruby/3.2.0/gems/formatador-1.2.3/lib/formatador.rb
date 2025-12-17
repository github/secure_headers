# frozen_string_literal: true

require File.join(File.dirname(__FILE__), 'formatador', 'table')
require File.join(File.dirname(__FILE__), 'formatador', 'progressbar')

require 'reline' # for table char width calculations

class Formatador
  VERSION = '1.2.3'

  STYLES = {
    "\/": '0',
    reset: '0',
    bold: '1',
    faint: '2',
    underline: '4',
    blink_slow: '5',
    blink_fast: '6',
    negative: '7', # invert color/color
    normal: '22',
    underline_none: '24',
    blink_off: '25',
    positive: '27', # revert color/color
    _black_: '40',
    _red_: '41',
    _green_: '42',
    _yellow_: '43',
    _blue_: '44',
    _magenta_: '45',
    _purple_: '45',
    _cyan_: '46',
    _white_: '47',
    _light_black_: '100',
    _light_red_: '101',
    _light_green_: '102',
    _light_yellow_: '103',
    _light_blue_: '104',
    _light_magenta_: '105',
    _light_purple_: '105',
    _light_cyan_: '106',
    black: '30',
    red: '31',
    green: '32',
    yellow: '33',
    blue: '34',
    magenta: '35',
    purple: '35',
    cyan: '36',
    white: '37',
    light_black: '90',
    light_red: '91',
    light_green: '92',
    light_yellow: '93',
    light_blue: '94',
    light_magenta: '95',
    light_purple: '95',
    light_cyan: '96'
  }.freeze

  PARSE_REGEX  = /\[(#{STYLES.keys.join('|')})\]/ix.freeze
  INDENT_REGEX = /\[indent\]/ix.freeze

  def initialize
    @indent = 1
  end

  def display(string = '')
    print(parse("[indent]#{string}"))
    $stdout.flush
    nil
  end

  def display_line(string = '')
    display(string)
    new_line
    nil
  end

  def display_lines(lines = [])
    [*lines].each do |line|
      display_line(line)
    end
    nil
  end

  def parse(string)
    if color_support
      string.gsub(PARSE_REGEX) { "\e[#{STYLES[::Regexp.last_match(1).to_sym]}m" }.gsub(INDENT_REGEX) { indentation }
    else
      strip(string)
    end
  end

  def indent
    @indent += 1
    yield
  ensure
    @indent -= 1
  end

  def indentation
    '  ' * @indent
  end

  def redisplay(string = '', width = 120)
    print("\r#{' ' * width}\r")
    display(string.to_s)
    nil
  end

  def redisplay_line(string = '', width = 120)
    redisplay(string, width)
    new_line
    nil
  end

  def new_line
    print("\n")
    nil
  end

  def set_title(title)
    print("\033]0;#{title}\007")
    $stdout.flush
    nil
  end

  def strip(string)
    string.gsub(PARSE_REGEX, '').gsub(INDENT_REGEX) { indentation }
  end

  %w[display display_line display_lines indent parse redisplay redisplay_line new_line redisplay_progressbar set_title].each do |method|
    eval <<-DEF
      def self.#{method}(*args, &block)
        Thread.current[:formatador] ||= new
        Thread.current[:formatador].#{method}(*args, &block)
      end
    DEF
  end

  %w[display_table display_compact_table].each do |method|
    eval <<-DEF
      def self.#{method}(*args, **kwargs, &block)
        Thread.current[:formatador] ||= new
        Thread.current[:formatador].#{method}(*args, **kwargs, &block)
      end
    DEF
  end

  private

  def color_support
    @color_support ||= $stdout.tty? || ENV['GITHUB_ACTIONS'] == 'true'
  end
end
