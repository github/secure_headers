# frozen_string_literal: true

require ::File.expand_path("test_helper", __dir__)

class PryNavTest < Test::Unit::TestCase
  # removing color makes string matching easier
  def setup
    Pry.color = false
  end

  # lifted from:
  # https://github.com/pry/pry-stack_explorer/blob/e3e6bd202e092712900f0d5f239ee21ab2f32b2b/test/support/io_utils.rb
  def with_pry_output_captured(new_in, new_out = StringIO.new)
    old_in = Pry.input
    old_out = Pry.output

    # direct stdout so we can test against `puts` in the method we defined above
    old_stdout = $stdout
    $stdout = new_out

    Pry.input = new_in
    Pry.output = new_out

    begin
      yield
    ensure
      Pry.input = old_in
      Pry.output = old_out
      $stdout = old_stdout
    end

    new_out
  end

  # `step` will step into the frames, while `next` keeps the debugging execution within the frame
  def test_step
    o = NavSample.new

    r = with_pry_output_captured(
      InputTester.new(
        "step",

        "step",
        "step",

        "continue"
      )
    ){ o.nested_bind_with_call }

    # initial binding display
    assert(r.string.include?("def nested_bind_with_call"))

    # after two steps, we are in the second frame, let's make sure we get there
    assert(r.string.include?("def nested_bind_call"))

    assert(/nested_puts\n/ =~ r.string)
    assert(/root_puts\n/ =~ r.string)
  end

  def test_next
    o = NavSample.new

    r = with_pry_output_captured(
      InputTester.new(
        "next",
        "next",
        "next",
        "continue"
      )
    ){ o.nested_bind_with_call }

    assert(r.string.include?("def nested_bind_with_call"))
    refute(r.string.include?("def nested_bind_call"))

    assert(/nested_puts\n/ =~ r.string)
    assert(/root_puts\n/ =~ r.string)
  end

  def test_continue
    o = NavSample.new

    r = with_pry_output_captured(
      InputTester.new(
        "continue",
      )
    ){ o.nested_bind_with_call }

    assert(r.string.include?("def nested_bind_with_call"))
    refute(r.string.include?("def nested_bind_call"))

    assert(/nested_puts\n/ =~ r.string)
    assert(/root_puts\n/ =~ r.string)
  end

  def test_file_context
    assert(PryNav.check_file_context(binding))
  end
end