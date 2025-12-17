# coding: utf-8
Shindo.tests("Formatador: tables") do

output = <<-OUTPUT
    +---+
    | [bold]a[/] |
    +---+
    | 1 |
    +---+
    | 2 |
    +---+
OUTPUT
output = Formatador.parse(output)

  tests("#display_table([{:a => 1}, {:a => 2}])").returns(output) do
    capture_stdout do
      Formatador.display_table([{:a => 1}, {:a => 2}])
    end
  end

output = <<-OUTPUT
    +--------+
    | [bold]header[/] |
    +--------+
    +--------+
OUTPUT
output = Formatador.parse(output)

  tests("#display_table([], [:header])").returns(output) do
    capture_stdout do
      Formatador.display_table([], [:header])
    end
  end

output = <<-OUTPUT
    +--------+
    | [bold]header[/] |
    +--------+
    |        |
    +--------+
OUTPUT
output = Formatador.parse(output)

  tests("#display_table([{:a => 1}], [:header])").returns(output) do
    capture_stdout do
      Formatador.display_table([{:a => 1}], [:header])
    end
  end



output = <<-OUTPUT
    +---+------------+
    | [bold]a[/] | [bold]nested.key[/] |
    +---+------------+
    | 1 | value      |
    +---+------------+
OUTPUT
output = Formatador.parse(output)

  tests("#display_table([{:a => 1, :nested => {:key => 'value'}}], [:header, :'nested.key'])").returns(output) do
    capture_stdout do
      Formatador.display_table([{:a => 1, :nested => {:key => 'value'}}], [:a, :'nested.key'])
    end
  end


if (RUBY_VERSION.split('.').map(&:to_i) <=> [3, 4, 0]).positive?
output = <<-OUTPUT
    +---+----------------+
    | [bold]a[/] | [bold]nested[/]         |
    +---+----------------+
    | 1 | {key: "value"} |
    +---+----------------+
OUTPUT
else
output = <<-OUTPUT
    +---+-----------------+
    | [bold]a[/] | [bold]nested[/]          |
    +---+-----------------+
    | 1 | {:key=>"value"} |
    +---+-----------------+
OUTPUT
end
output = Formatador.parse(output)

  tests("#display_table([{:a => 1, :nested => {:key => 'value'}}])").returns(output) do
    capture_stdout do
      Formatador.display_table([{:a => 1, :nested => {:key => 'value'}}])
    end
  end

output = <<-OUTPUT
    +---+--------------+
    | [bold]a[/] | [bold]just.pointed[/] |
    +---+--------------+
    | 1 | value        |
    +---+--------------+
OUTPUT
output = Formatador.parse(output)

  tests("#display_table([{:a => 1, 'just.pointed' => :value}])").returns(output) do
    capture_stdout do
      Formatador.display_table([{:a => 1, 'just.pointed' => :value}])
    end
  end

output = <<-OUTPUT
    +-------------------------+----------------+
    | [bold]right-justify a numeric[/] | [bold]standard value[/] |
    +-------------------------+----------------+
    |                   12345 | value          |
    +-------------------------+----------------+
OUTPUT
output = Formatador.parse(output)

  tests("#display_table([{'right-justify a numeric' => 12345, 'standard value' => 'standard value'}], numeric_rjust: true)").returns(output) do
    capture_stdout do
      Formatador.display_table([{'right-justify a numeric' => 12345, 'standard value' => 'value'}], numeric_rjust: true)
    end
  end

output = <<-OUTPUT
    +--------+------------+
    | [bold]header[/] | [bold]nested.key[/] |
    +--------+------------+
    |  12345 | value      |
    +--------+------------+
OUTPUT
output = Formatador.parse(output)

  tests("#display_table([{:header => 12345, :nested => {:key => value}}], [:header, :'nested.key'], numeric_rjust: true)").returns(output) do
    capture_stdout do
      Formatador.display_table([{:header => 12345, :nested => {:key => 'value'}}], [:header, :'nested.key'], numeric_rjust: true)
    end
  end


output = <<-OUTPUT
    +------+
    | [bold]a[/]    |
    +------+
    | 1    |
    +------+
    | 震度 |
    +------+
OUTPUT
  output = Formatador.parse(output)

  tests("#display_table([{:a => 1}, {:a => '震度'}])").returns(output) do
    capture_stdout do
      Formatador.display_table([{:a => 1}, {:a => "震度"}])
    end
  end

output = <<-OUTPUT
    +----+
    | [bold]a[/]  |
    +----+
    | 1  |
    +----+
    | 🤷 |
    +----+
OUTPUT
  output = Formatador.parse(output)

  tests("#display_table([{:a => 1}, {:a => '🤷'}])").returns(output) do
    capture_stdout do
      Formatador.display_table([{:a => 1}, {:a => '🤷'}])
    end
  end


end
