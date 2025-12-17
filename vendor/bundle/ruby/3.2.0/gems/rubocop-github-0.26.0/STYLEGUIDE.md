# Ruby Style Guide

This is GitHub's Ruby Style Guide, inspired by [RuboCop's guide][rubocop-guide].

## Table of Contents

1. [Layout](#layout)
   1. [Indentation](#indentation)
   2. [Inline](#inline)
   3. [Newlines](#newlines)
2. [Maximum Line Length](#line-length)
3. [Classes](#classes)
4. [Collections](#collections)
5. [Documentation](#documentation)
6. [Dynamic Dispatch](#dynamic-dispatch)
7. [Exceptions](#exceptions)
8. [Hashes](#hashes)
9. [Keyword Arguments](#keyword-arguments)
10. [Naming](#naming)
11. [Percent Literals](#percent-literals)
12. [Regular Expressions](#regular-expressions)
13. [Requires](#requires)
14. [Strings](#strings)
15. [Methods](#methods)
    1. [Method definitions](#method-definitions)
    2. [Method calls](#method-calls)
16. [Conditional Expressions](#conditional-expressions)
    1. [Conditional keywords](#conditional-keywords)
    2. [Ternary operator](#ternary-operator)
17. [Syntax](#syntax)
18. [Rails](#rails)
    1. [content_for](#content_for)
    2. [Instance Variables in Views](#instance-variables-in-views)

## Layout

### Indentation

* Use soft-tabs with a two space indent.
  <a name="default-indentation"></a><sup>[[link](#default-indentation)]</sup>
  * <a href="https://docs.rubocop.org/rubocop/cops_layout.html#layoutindentationstyle">RuboCop rule: Layout/IndentationStyle</a>

* Indent `when` with the start of the `case` expression.
  <a name="indent-when-as-start-of-case"></a><sup>[[link](#indent-when-as-start-of-case)]</sup>
  * <a href="https://docs.rubocop.org/rubocop/cops_layout.html#layoutcaseindentation">RuboCop rule: Layout/CaseIndentation</a>

``` ruby
# bad
message = case
          when song.name == "Misty"
            "Not again!"
          when song.duration > 120
            "Too long!"
          when Time.now.hour > 21
            "It's too late"
          else
            song.to_s
          end

# good
message = case
when song.name == "Misty"
  "Not again!"
when song.duration > 120
  "Too long!"
when Time.now.hour > 21
  "It's too late"
else
  song.to_s
end

# good
case
when song.name == "Misty"
  puts "Not again!"
when song.duration > 120
  puts "Too long!"
when Time.now.hour > 21
  puts "It's too late"
else
  song.play
end
```

### Inline

* Never leave trailing whitespace.
  <a name="trailing-whitespace"></a><sup>[[link](#trailing-whitespace)]</sup>
  * <a href="https://docs.rubocop.org/rubocop/cops_layout.html#layouttrailingwhitespace">RuboCop rule: Layout/TrailingWhitespace</a>

* Use spaces around operators, after commas, colons and semicolons, around `{`
  and before `}`.
  <a name="spaces-operators"></a><sup>[[link](#spaces-operators)]</sup>
  * <a href="https://docs.rubocop.org/rubocop/cops_layout.html#layoutspacearoundoperators">RuboCop rule: Layout/SpaceAroundOperators</a>
  * <a href="https://docs.rubocop.org/rubocop/cops_layout.html#layoutspaceaftercomma">RuboCop rule: Layout/SpaceAfterComma</a>
  * <a href="https://docs.rubocop.org/rubocop/cops_layout.html#layoutspaceaftercolon">RuboCop rule: Layout/SpaceAfterColon</a>
  * <a href="https://docs.rubocop.org/rubocop/cops_layout.html#layoutspacebeforeblockbraces">RuboCop rule: Layout/SpaceBeforeBlockBraces</a>
  * <a href="https://docs.rubocop.org/rubocop/cops_layout.html#layoutspaceinsidehashliteralbraces">RuboCop rule: Layout/SpaceInsideHashLiteralBraces</a>
  * <a href="https://docs.rubocop.org/rubocop/cops_style.html#stylehashsyntax">RuboCop rule: Style/HashSyntax</a>
  * <a href="https://docs.rubocop.org/rubocop/cops_layout.html#layoutspacearoundoperators">RuboCop rule: Layout/SpaceAroundOperators</a>

``` ruby
sum = 1 + 2
a, b = 1, 2
1 > 2 ? true : false; puts "Hi"
[1, 2, 3].each { |e| puts e }
```

* No spaces after `(`, `[` or before `]`, `)`.
  <a name="no-spaces-braces"></a><sup>[[link](#no-spaces-braces)]</sup>
  * <a href="https://docs.rubocop.org/rubocop/cops_layout.html#layoutspaceinsideparens">RuboCop rule: Layout/SpaceInsideParens</a>
  * <a href="https://docs.rubocop.org/rubocop/cops_layout.html#layoutspaceinsidereferencebrackets">RuboCop rule: Layout/SpaceInsideReferenceBrackets</a>

``` ruby
some(arg).other
[1, 2, 3].length
```

* No spaces after `!`.
  <a name="no-spaces-bang"></a><sup>[[link](#no-spaces-bang)]</sup>
  * <a href="https://docs.rubocop.org/rubocop/cops_layout.html#layoutspaceafternot">RuboCop rule: Layout/SpaceAfterNot</a>

``` ruby
!array.include?(element)
```

### Newlines

* End each file with a [newline](https://github.com/bbatsov/ruby-style-guide#newline-eof).
  <a name="newline-eof"></a><sup>[[link](#newline-eof)]</sup>
  * <a href="https://docs.rubocop.org/rubocop/cops_layout.html#layouttrailingemptylines">RuboCop rule: Layout/TrailingEmptyLines</a>

* Use empty lines between `def`s and to break up a method into logical
  paragraphs.
  <a name="empty-lines-def"></a><sup>[[link](#empty-lines-def)]</sup>
  * <a href="https://docs.rubocop.org/rubocop/cops_layout.html#layoutemptylinebetweendefs">RuboCop rule: Layout/EmptyLineBetweenDefs</a>

``` ruby
def some_method
  data = initialize(options)

  data.manipulate!

  data.result
end

def some_method
  result
end
```

## Maximum Line Length

* Keep each line of code to a readable length. Unless you have a reason to, keep lines to a maximum of 118 characters. Why 118? That's the width at which the pull request diff UI needs horizontal scrolling (making pull requests harder to review).
  <a name="line-length"></a><sup>[[link](#line-length)]</sup>
  * <a href="https://docs.rubocop.org/rubocop/cops_layout.html#layoutlinelength">RuboCop rule: Layout/LineLength</a>

## Classes

* Avoid the usage of class (`@@`) variables due to their unusual behavior
in inheritance.
  <a name="class-variables"></a><sup>[[link](#class-variables)]</sup>
  * <a href="https://docs.rubocop.org/rubocop/cops_style.html#styleclassvars">RuboCop rule: Style/ClassVars</a>

``` ruby
class Parent
  @@class_var = "parent"

  def self.print_class_var
    puts @@class_var
  end
end

class Child < Parent
  @@class_var = "child"
end

Parent.print_class_var # => will print "child"
```

    As you can see all the classes in a class hierarchy actually share one
    class variable. Class instance variables should usually be preferred
    over class variables.

* Use `def self.method` to define singleton methods. This makes the methods
  more resistant to refactoring changes.
  <a name="singleton-methods"></a><sup>[[link](#singleton-methods)]</sup>
  * <a href="https://docs.rubocop.org/rubocop/cops_style.html#styleclassmethodsdefinitions">RuboCop rule: Style/ClassMethodsDefinitions</a>

``` ruby
class TestClass
  # bad
  def TestClass.some_method
    # body omitted
  end

  # good
  def self.some_other_method
    # body omitted
  end
```

* Avoid `class << self` except when necessary, e.g. single accessors and aliased
  attributes.
  <a name="class-method-definitions"></a><sup>[[link](#class-method-definitions)]</sup>
  * <a href="https://docs.rubocop.org/rubocop/cops_style.html#styleclassmethodsdefinitions">RuboCop rule: Style/ClassMethodsDefinitions</a>

``` ruby
class TestClass
  # bad
  class << self
    def first_method
      # body omitted
    end

    def second_method_etc
      # body omitted
    end
  end

  # good
  class << self
    attr_accessor :per_page
    alias_method :nwo, :find_by_name_with_owner
  end

  def self.first_method
    # body omitted
  end

  def self.second_method_etc
    # body omitted
  end
end
```

* Indent the `public`, `protected`, and `private` methods as much the
  method definitions they apply to. Leave one blank line above them.
  <a name="access-modifier-identation"></a><sup>[[link](#access-modifier-identation)]</sup>
  * <a href="https://docs.rubocop.org/rubocop/cops_layout.html#layoutaccessmodifierindentation">RuboCop rule: Layout/AccessModifierIndentation</a>
  * <a href="https://docs.rubocop.org/rubocop/cops_layout.html#layoutemptylinesaroundaccessmodifier">RuboCop rule: Layout/EmptyLinesAroundAccessModifier</a>

``` ruby
class SomeClass
  def public_method
    # ...
  end

  private
  def private_method
    # ...
  end
end
```

* Avoid explicit use of `self` as the recipient of internal class or instance
  messages unless to specify a method shadowed by a variable.
  <a name="self-messages"></a><sup>[[link](#self-messages)]</sup>
  * <a href="https://docs.rubocop.org/rubocop/cops_style.html#styleredundantself">RuboCop rule: Style/RedundantSelf</a>

``` ruby
class SomeClass
  attr_accessor :message

  def greeting(name)
    message = "Hi #{name}" # local variable in Ruby, not attribute writer
    self.message = message
  end
end
```

## Collections

* Prefer `%w` to the literal array syntax when you need an array of
strings.
  <a name="percent-w"></a><sup>[[link](#percent-w)]</sup>
  * <a href="https://docs.rubocop.org/rubocop/cops_style.html#stylewordarray">RuboCop rule: Style/WordArray</a>

``` ruby
# bad
STATES = ["draft", "open", "closed"]

# good
STATES = %w(draft open closed)
```

* Use `Set` instead of `Array` when dealing with unique elements. `Set`
  implements a collection of unordered values with no duplicates. This
  is a hybrid of `Array`'s intuitive inter-operation facilities and
  `Hash`'s fast lookup.
  <a name="prefer-set"></a><sup>[[link](#prefer-set)]</sup>

* Use symbols instead of strings as hash keys.
  <a name="symbols-as-keys"></a><sup>[[link](#symbols-as-keys)]</sup>
  * <a href="https://docs.rubocop.org/rubocop/cops_style.html#stylestringhashkeys">RuboCop rule: Style/StringHashKeys</a>

``` ruby
# bad
hash = { "one" => 1, "two" => 2, "three" => 3 }

# good
hash = { one: 1, two: 2, three: 3 }
```

## Documentation

Use [TomDoc](http://tomdoc.org) to the best of your ability. It's pretty sweet:
<a name="tomdoc"></a><sup>[[link](#tomdoc)]</sup>

``` ruby
# Public: Duplicate some text an arbitrary number of times.
#
# text  - The String to be duplicated.
# count - The Integer number of times to duplicate the text.
#
# Examples
#
#   multiplex("Tom", 4)
#   # => "TomTomTomTom"
#
# Returns the duplicated String.
def multiplex(text, count)
  text * count
end
```

## Dynamic Dispatch

Avoid calling `send` and its cousins unless you really need it. Metaprogramming can be extremely powerful, but in most cases you can write code that captures your meaning by being explicit:
<a name="avoid-send"></a><sup>[[link](#avoid-send)]</sup>
  * <a href="https://docs.rubocop.org/rubocop/cops_style.html#stylesend">RuboCop rule: Style/Send</a>

``` ruby
# avoid
unless [:base, :head].include?(base_or_head)
  raise ArgumentError, "base_or_head must be either :base or :head"
end

repository = pull.send("#{base_or_head}_repository")
branch = pull.send("#{base_or_head}_ref_name")

# prefer
case base_or_head
when :base
  repository = pull.base_repository
  branch = pull.base_ref_name
when :head
  repository = pull.head_repository
  branch = pull.head_ref_name
else
  raise ArgumentError, "base_or_head must be either :base or :head"
end
```
## Exceptions

* Don't use exceptions for flow of control.
  <a name="exceptions-flow-control"></a><sup>[[link](#exceptions-flow-control)]</sup>

``` ruby
# bad
begin
  n / d
rescue ZeroDivisionError
  puts "Cannot divide by 0!"
end

# good
if d.zero?
  puts "Cannot divide by 0!"
else
  n / d
end
```

* Rescue specific exceptions, not `StandardError` or its superclasses.
  <a name="specific-exceptions"></a><sup>[[link](#specific-exceptions)]</sup>

``` ruby
# bad
begin
  # an exception occurs here
rescue
  # exception handling
end

# still bad
begin
  # an exception occurs here
rescue Exception
  # exception handling
end
```

## Hashes

Use the Ruby 1.9 syntax for hash literals when all the keys are symbols:
<a name="symbols-as-hash-keys"></a><sup>[[link](#symbols-as-hash-keys)]</sup>
* <a href="https://docs.rubocop.org/rubocop/cops_style.html#stylestringhashkeys">RuboCop rule: Style/StringHashKeys</a>

``` ruby
# bad
user = {
  :login => "defunkt",
  :name => "Chris Wanstrath"
}

# good
user = {
  login: "defunkt",
  name: "Chris Wanstrath"
}
```

Use the 1.9 syntax when calling a method with Hash options arguments or named arguments:
<a name="symbols-as-hash-method-arguments"></a><sup>[[link](#symbols-as-hash-method-arguments)]</sup>

``` ruby
# bad
user = User.create(:login => "jane")
link_to("Account", :controller => "users", :action => "show", :id => user)

# good
user = User.create(login: "jane")
link_to("Account", controller: "users", action: "show", id: user)
```

If you have a hash with mixed key types, use the legacy hashrocket style to avoid mixing styles within the same hash:
<a name="consistent-hash-syntax"></a><sup>[[link](#consistent-hash-syntax)]</sup>
* <a href="https://docs.rubocop.org/rubocop/cops_style.html#stylehashsyntax">RuboCop rule: Style/HashSyntax</a>

``` ruby

``` ruby
# bad
hsh = {
  user_id: 55,
  "followers-count" => 1000
}

# good
hsh = {
  :user_id => 55,
  "followers-count" => 1000
}
```

## Keyword Arguments

[Keyword arguments](http://magazine.rubyist.net/?Ruby200SpecialEn-kwarg) are recommended but not required when a method's arguments may otherwise be opaque or non-obvious when called. Additionally, prefer them over the old "Hash as pseudo-named args" style from pre-2.0 ruby.
<a name="keyword-arguments"></a><sup>[[link](#keyword-arguments)]</sup>
* <a href="https://docs.rubocop.org/rubocop/cops_style.html#styleoptionalbooleanparameter">RuboCop rule: Style/OptionalBooleanParameter</a>

So instead of this:

``` ruby
def remove_member(user, skip_membership_check=false)
  # ...
end

# Elsewhere: what does true mean here?
remove_member(user, true)
```

Do this, which is much clearer:

``` ruby
def remove_member(user, skip_membership_check: false)
  # ...
end

# Elsewhere, now with more clarity:
remove_member(user, skip_membership_check: true)
```

## Naming

* Use `snake_case` for methods and variables.
  <a name="snake-case-methods-vars"></a><sup>[[link](#snake-case-methods-vars)]</sup>
  * <a href="https://docs.rubocop.org/rubocop/cops_naming.html#namingsnakecase">RuboCop rule: Naming/SnakeCase</a>
  * <a href="https://docs.rubocop.org/rubocop/cops_naming.html#namingvariablename">RuboCop rule: Naming/VariableName</a>

* Use `CamelCase` for classes and modules.  (Keep acronyms like HTTP,
  RFC, XML uppercase.)
  <a name="camelcase-classes-modules"></a><sup>[[link](#camelcase-classes-modules)]</sup>
  * <a href="https://docs.rubocop.org/rubocop/cops_naming.html#namingclassandmodulecamelcase">RuboCop rule: Naming/ClassAndModuleCamelCase</a>

* Use `SCREAMING_SNAKE_CASE` for other constants.
  <a name="screaming-snake-case-constants"></a><sup>[[link](#screaming-snake-case-constants)]</sup>
  * <a href="https://docs.rubocop.org/rubocop/cops_naming.html#namingconstantname">RuboCop rule: Naming/ConstantName</a>

* The names of predicate methods (methods that return a boolean value)
  should end in a question mark. (i.e. `Array#empty?`).
  <a name="bool-methods-qmark"></a><sup>[[link](#bool-methods-qmark)]</sup>
  * <a href="https://docs.rubocop.org/rubocop/cops_naming.html#namingpredicatename">RuboCop rule: Naming/PredicateName</a>

* The names of potentially "dangerous" methods (i.e. methods that modify `self` or the
  arguments, `exit!`, etc.) should end with an exclamation mark. Bang methods
  should only exist if a non-bang counterpart (method name which does NOT end with !)
  also exists.
  <a name="dangerous-method-bang"></a><sup>[[link](#dangerous-method-bang)]</sup>

## Percent Literals

* Use `%w` freely.
  <a name="use-percent-w-freely"></a><sup>[[link](#use-percent-w-freely)]</sup>
  * <a href="https://docs.rubocop.org/rubocop/cops_style.html#stylewordarray">RuboCop rule: Style/WordArray</a>

``` ruby
STATES = %w(draft open closed)
```

* Use `%()` for single-line strings which require both interpolation
  and embedded double-quotes. For multi-line strings, prefer heredocs.
  <a name="percent-parens-single-line"></a><sup>[[link](#percent-parens-single-line)]</sup>
  * <a href="https://docs.rubocop.org/rubocop/cops_style.html#stylebarepercentliterals">RuboCop rule: Style/BarePercentLiterals</a>

``` ruby
# bad (no interpolation needed)
%(<div class="text">Some text</div>)
# should be "<div class=\"text\">Some text</div>"

# bad (no double-quotes)
%(This is #{quality} style)
# should be "This is #{quality} style"

# bad (multiple lines)
%(<div>\n<span class="big">#{exclamation}</span>\n</div>)
# should be a heredoc.

# good (requires interpolation, has quotes, single line)
%(<tr><td class="name">#{name}</td>)
```

* Use `%r` only for regular expressions matching *more than* one '/' character.
  <a name="percent-r-regular-expressions"></a><sup>[[link](#percent-r-regular-expressions)]</sup>
  * <a href="https://docs.rubocop.org/rubocop/cops_style.html#styleregexpliteral">RuboCop rule: Style/RegexpLiteral</a>

``` ruby
# bad
%r(\s+)

# still bad
%r(^/(.*)$)
# should be /^\/(.*)$/

# good
%r(^/blog/2011/(.*)$)
```

## Regular Expressions

* Avoid using $1-9 as it can be hard to track what they contain. Named groups
  can be used instead.
  <a name="capture-with-named-groups"></a><sup>[[link](#capture-with-named-groups)]</sup>
  * <a href="https://docs.rubocop.org/rubocop/cops_lint.html#mixedregexpcapturetypes">RuboCop rule: Lint/MixedRegexpCaptureTypes</a>
``` ruby
# bad
/(regexp)/ =~ string
...
process $1

# good
/(?<meaningful_var>regexp)/ =~ string
...
process meaningful_var
```

* Be careful with `^` and `$` as they match start/end of line, not string endings.
  If you want to match the whole string use: `\A` and `\z`.
  <a name="regex-begin-end-markers"></a><sup>[[link](#regex-begin-end-markers)]</sup>

``` ruby
string = "some injection\nusername"
string[/^username$/]   # matches
string[/\Ausername\z/] # don't match
```

* Use `x` modifier for complex regexps. This makes them more readable and you
  can add some useful comments. Just be careful as spaces are ignored.
  <a name="x-modifier-complex-regex"></a><sup>[[link](#x-modifier-complex-regex)]</sup>

``` ruby
regexp = %r{
  start         # some text
  \s            # white space char
  (group)       # first group
  (?:alt1|alt2) # some alternation
  end
}x
```

## Requires

Always `require` dependencies used directly in a script at the start of the same file.
Resources that will get autoloaded on first use—such as Rails models, controllers, or
helpers—don't need to be required.
<a name="require-dependencies-directly"></a><sup>[[link](#require-dependencies-directly)]</sup>

``` ruby
require "set"
require "time"

%w(foo bar).to_set
Time.parse("2015-10-21")
```

This not only loads the necessary dependencies if they haven't already, but acts as
documentation about the libraries that the current file uses.

## Strings

* Prefer string interpolation instead of string concatenation:
  <a name="string-interpolation"></a><sup>[[link](#string-interpolation)]</sup>
  * <a href="https://docs.rubocop.org/rubocop/cops_style.html#stylestringconcatenation">RuboCop rule: Style/StringConcatenation</a>

``` ruby
# bad
email_with_name = user.name + " <" + user.email + ">"

# good
email_with_name = "#{user.name} <#{user.email}>"
```

* Use double-quoted strings. Interpolation and escaped characters
  will always work without a delimiter change, and `'` is a lot more
  common than `"` in string literals.
  <a name="double-quotes"></a><sup>[[link](#double-quotes)]</sup>
  * <a href="https://docs.rubocop.org/rubocop/cops_style.html#stylestringliterals">RuboCop rule: Style/StringLiterals</a>

``` ruby
# bad
name = 'Bozhidar'

# good
name = "Bozhidar"
```

* Avoid using `String#+` when you need to construct large data chunks.
  Instead, use `String#<<`. Concatenation mutates the string instance in-place
  and is always faster than `String#+`, which creates a bunch of new string objects.
  <a name="string-concatenation"></a><sup>[[link](#string-concatenation)]</sup>

``` ruby
# good and also fast
html = ""
html << "<h1>Page title</h1>"

paragraphs.each do |paragraph|
  html << "<p>#{paragraph}</p>"
end
```

## Methods

### Method definitions

* Use `def` with parentheses when there are arguments. Omit the
  parentheses when the method doesn't accept any arguments.
  <a name="method-parens-when-arguments"></a><sup>[[link](#method-parens-when-arguments)]</sup>
  * <a href="https://docs.rubocop.org/rubocop/cops_style.html#styledefwithparentheses">RuboCop rule: Style/DefWithParentheses</a>

 ``` ruby
 def some_method
   # body omitted
 end

 def some_method_with_arguments(arg1, arg2)
   # body omitted
 end
 ```

### Method calls

* If the first argument to a method begins with an open parenthesis,
  always use parentheses in the method invocation. For example, write
  `f((3 + 2) + 1)`.
  <a name="parens-no-spaces"></a><sup>[[link](#parens-no-spaces)]</sup>
  * <a href="https://docs.rubocop.org/rubocop/cops_style.html#stylemethodcallwithargsparentheses">RuboCop rule: Style/MethodCallWithArgsParentheses</a>

* Never put a space between a method name and the opening parenthesis.
  <a name="no-spaces-method-parens"></a><sup>[[link](#no-spaces-method-parens)]</sup>
  * <a href="https://docs.rubocop.org/rubocop/cops_lint.html#lintparenthesesasgroupedexpression">RuboCop rule: Lint/ParenthesesAsGroupedExpression</a>

``` ruby
# bad
f (3 + 2) + 1

# good
f(3 + 2) + 1
```

## Conditional Expressions

### Conditional keywords

* Never use `then` for multi-line `if/unless`.
  <a name="no-then-for-multi-line-if-unless"></a><sup>[[link](#no-then-for-multi-line-if-unless)]</sup>
  * <a href="https://docs.rubocop.org/rubocop/cops_style.html#stylemultilineifthen">RuboCop rule: Style/MultilineIfThen</a>

``` ruby
# bad
if some_condition then
  # body omitted
end

# good
if some_condition
  # body omitted
end
```

* The `and` and `or` keywords are banned. It's just not worth it. Always use `&&` and `||` instead.
  <a name="no-and-or-or"></a><sup>[[link](#no-and-or-or)]</sup>
  * <a href="https://docs.rubocop.org/rubocop/cops_style.html#styleandor">RuboCop rule: Style/AndOr</a>

* Favor modifier `if/unless` usage when you have a single-line
  body.
  <a name="favor-modifier-if-unless"></a><sup>[[link](#favor-modifier-if-unless)]</sup>
  * <a href="https://docs.rubocop.org/rubocop/cops_style.html#stylemultilineternaryoperator">RuboCop rule: Style/MultilineTernaryOperator</a>

``` ruby
# bad
if some_condition
  do_something
end

# good
do_something if some_condition
```

* Never use `unless` with `else`. Rewrite these with the positive case first.
  <a name="no-else-with-unless"></a><sup>[[link](#no-else-with-unless)]</sup>
  * <a href="https://docs.rubocop.org/rubocop/cops_style.html#styleunlesselse">RuboCop rule: Style/UnlessElse</a>

``` ruby
# bad
unless success?
  puts "failure"
else
  puts "success"
end

# good
if success?
  puts "success"
else
  puts "failure"
end
```

* Don't use parentheses around the condition of an `if/unless/while`.
  <a name="no-parens-if-unless-while"></a><sup>[[link](#no-parens-if-unless-while)]</sup>
  * <a href="https://docs.rubocop.org/rubocop/cops_style.html#styleparenthesesaroundcondition">RuboCop rule: Style/ParenthesesAroundCondition</a>

``` ruby
# bad
if (x > 10)
  # body omitted
end

# good
if x > 10
  # body omitted
end
```

* Don't use `unless` with a negated condition.
  <a name="no-unless-negation"></a><sup>[[link](#no-unless-negation)]</sup>
  * <a href="https://docs.rubocop.org/rubocop/cops_style.html#stylenegatedunless">RuboCop rule: Style/NegatedUnless</a>

```ruby
# bad
unless !condition?
  do_something
end

# good
if condition?
  do_something
end
```

### Ternary operator

* Avoid the ternary operator (`?:`) except in cases where all expressions are extremely
  trivial. However, do use the ternary operator(`?:`) over `if/then/else/end` constructs
  for single line conditionals.
  <a name="trivial-ternary"></a><sup>[[link](#trivial-ternary)]</sup>
  * <a href="https://docs.rubocop.org/rubocop/cops_style.html#stylemultilineternaryoperator">RuboCop rule: Style/MultilineTernaryOperator</a>

``` ruby
# bad
result = if some_condition then something else something_else end

# good
result = some_condition ? something : something_else
```

* Avoid multi-line `?:` (the ternary operator), use `if/unless` instead.
  <a name="no-multiline-ternary"></a><sup>[[link](#no-multiline-ternary)]</sup>
  * <a href="https://docs.rubocop.org/rubocop/cops_style.html#stylemultilineternaryoperator">RuboCop rule: Style/MultilineTernaryOperator</a>

* Use one expression per branch in a ternary operator. This
  also means that ternary operators must not be nested. Prefer
  `if/else` constructs in these cases.
  <a name="one-expression-per-branch"></a><sup>[[link](#one-expression-per-branch)]</sup>
  * <a href="https://docs.rubocop.org/rubocop/cops_style.html#stylenestedternaryoperator">RuboCop rule: Style/NestedTernaryOperator</a>

``` ruby
# bad
some_condition ? (nested_condition ? nested_something : nested_something_else) : something_else

# good
if some_condition
  nested_condition ? nested_something : nested_something_else
else
  something_else
end
```

## Syntax

* Never use `for`, unless you know exactly why. Most of the time iterators
  should be used instead. `for` is implemented in terms of `each` (so
  you're adding a level of indirection), but with a twist - `for`
  doesn't introduce a new scope (unlike `each`) and variables defined
  in its block will be visible outside it.
  <a name="avoid-for"></a><sup>[[link](#avoid-for)]</sup>
  * <a href="https://docs.rubocop.org/rubocop/cops_style.html#stylefor">RuboCop rule: Style/For</a>

``` ruby
arr = [1, 2, 3]

# bad
for elem in arr do
  puts elem
end

# good
arr.each { |elem| puts elem }
```

* Prefer `{...}` over `do...end` for single-line blocks.  Avoid using
  `{...}` for multi-line blocks (multiline chaining is always
  ugly). Always use `do...end` for "control flow" and "method
  definitions" (e.g. in Rakefiles and certain DSLs).  Avoid `do...end`
  when chaining.
  <a name="squiggly-braces"></a><sup>[[link](#squiggly-braces)]</sup>
  * <a href="https://docs.rubocop.org/rubocop/cops_style.html#styleblockdelimiters">RuboCop rule: Style/BlockDelimiters</a>

``` ruby
names = ["Bozhidar", "Steve", "Sarah"]

# good
names.each { |name| puts name }

# bad
names.each do |name|
  puts name
end

# good
names.select { |name| name.start_with?("S") }.map { |name| name.upcase }

# bad
names.select do |name|
  name.start_with?("S")
end.map { |name| name.upcase }
```

* Some will argue that multiline chaining would look OK with the use of `{...}`,
 but they should ask themselves: is this code really readable and can't the block's
 contents be extracted into nifty methods?

* Avoid `return` where not required.
  <a name="avoid-return"></a><sup>[[link](#avoid-return)]</sup>
  * <a href="https://docs.rubocop.org/rubocop/cops_style.html#styleredundantreturn">RuboCop rule: Style/RedundantReturn</a>

``` ruby
# bad
def some_method(some_arr)
  return some_arr.size
end

# good
def some_method(some_arr)
  some_arr.size
end
```

* Use spaces around the `=` operator when assigning default values to method parameters:
  <a name="spaces-around-equals"></a><sup>[[link](#spaces-around-equals)]</sup>
  * <a href="https://docs.rubocop.org/rubocop/cops_style.html#stylespacearoundequalsinparameterdefault">RuboCop rule: Style/SpaceAroundEqualsInParameterDefault</a>

``` ruby
# bad
def some_method(arg1=:default, arg2=nil, arg3=[])
  # do something...
end

# good
def some_method(arg1 = :default, arg2 = nil, arg3 = [])
  # do something...
end
```

While several Ruby books suggest the first style, the second is much more prominent
in practice (and arguably a bit more readable).

* Using the return value of `=` (an assignment) is ok.
  <a name="use-return-value-of-assignment"></a><sup>[[link](#use-return-value-of-assignment)]</sup>

``` ruby
# bad
if (v = array.grep(/foo/)) ...

# good
if v = array.grep(/foo/) ...

# also good - has correct precedence.
if (v = next_value) == "hello" ...
```

* Use `||=` freely to initialize variables.
  <a name="memoization-for-initialization"></a><sup>[[link](#memoize-away)]</sup>
  * <a href="https://docs.rubocop.org/rubocop/cops_style.html#styleorassignment">RuboCop rule: Style/OrAssignment</a>

``` ruby
# set name to Bozhidar, only if it's nil or false
name ||= "Bozhidar"
```

* Don't use `||=` to initialize boolean variables. (Consider what
  would happen if the current value happened to be `false`.)
  <a name="no-memoization-for-boolean"></a><sup>[[link](#no-memoization-for-boolean)]</sup>
  * <a href="https://docs.rubocop.org/rubocop/cops_style.html#styleorassignment">RuboCop rule: Style/OrAssignment</a>

``` ruby
# bad - would set enabled to true even if it was false
enabled ||= true

# good
enabled = true if enabled.nil?
```

* Avoid using Perl-style special variables (like `$0-9`, `$`,
  etc. ). They are quite cryptic and their use in anything but
  one-liner scripts is discouraged. Prefer long form versions such as
  `$PROGRAM_NAME`.
  <a name="no-cryptic-vars"></a><sup>[[link](#no-cryptic-vars)]</sup>
  * <a href="https://docs.rubocop.org/rubocop/cops_style.html#stylespecialglobalvars">RuboCop rule: Style/SpecialGlobalVars</a>

* Use `_` for unused block parameters.
  <a name="underscore-unused-vars"></a><sup>[[link](#underscore-unused-vars)]</sup>
  * <a href="https://docs.rubocop.org/rubocop/cops_lint.html#lintunusedblockargument">RuboCop rule: Lint/UnusedBlockArgument</a>

``` ruby
# bad
result = hash.map { |k, v| v + 1 }

# good
result = hash.map { |_, v| v + 1 }
```

* Don't use the `===` (threequals) operator to check types. `===` is mostly an
  implementation detail to support Ruby features like `case`, and it's not commutative.
  For example, `String === "hi"` is true and `"hi" === String` is false.
  Instead, use `is_a?` or `kind_of?` if you must.
  <a name="type-checking-is-a-kind-of"></a><sup>[[link](#type-checking-is-a-kind-of)]</sup>
  * <a href="https://docs.rubocop.org/rubocop/cops_style.html#stylecaseequality">RuboCop rule: Style/CaseEquality</a>

  Refactoring is even better. It's worth looking hard at any code that explicitly checks types.

## Rails

### content_for

Limit usage of `content_for` helper. The use of `content_for` is the same as setting an instance variable plus `capture`.

``` erb
<% content_for :foo do %>
  Hello
<% end %>
```

Is effectively the same as

``` erb
<% @foo_content = capture do %>
  Hello
<% end %>
```

See "Instance Variables in Views" below.

#### Common Anti-patterns

**Using `content_for` within the same template to capture data.**

Instead, just use `capture`.

``` erb
<!-- bad -->
<% content_for :page do %>
  Hello
<% end %>
<% if foo? %>
  <div class="container">
    <%= yield :page %>
  </div>
<% else %>
  <%= yield :page %>
<% end %>
```

Simply capture and use a local variable since the result is only needed in this template.

``` erb
<!-- good -->
<% page = capture do %>
  Hello
<% end %>
<% if foo? %>
  <div class="container">
    <%= page %>
  </div>
<% else %>
  <%= page %>
<% end %>
```

**Using `content_for` to pass content to a subtemplate.**

Instead, `render layout:` with a block.

``` erb
<!-- bad -->
<% content_for :page do %>
  Hello
<% end %>
<%= render partial: "page" %>
<!-- _page.html.erb -->
<div class="container">
  <%= yield :page %>
</div>
```

Pass the content in a block directly to the `render` function.

``` erb
<!-- good -->
<%= render layout: "page" do %>
  Hello
<% end %>
<!-- _page.html.erb -->
<div class="container">
  <%= yield %>
</div>
```

### Instance Variables in Views

In general, passing data between templates with instance variables is discouraged. This even applies from controllers to templates, not just between partials.

`:locals` can be used to pass data from a controller just like partials.

``` ruby
def show
  render "blob/show", locals: {
    :repository => current_repository,
    :commit     => current_commit,
    :blob       => current_blob
  }
end
```

Rails implicit renders are also discouraged.

Always explicitly render templates with a full directory path. This makes template callers easier to trace. You can find all the callers of `"app/view/site/hompage.html.erb"` with a simple project search for `"site/homepage"`.

``` ruby
def homepage
  render "site/homepage"
end
```

#### Exceptions

There are some known edge cases where you might be forced to use instance variables. In these cases, its okay to do so.

##### Legacy templates

If you need to call a subview that expects an instance variable be set. If possible consider refactoring the subview to accept a local instead.

##### Layouts

Unfortunately the only way to get data into a layout template is with instance variables. You can't explicitly pass locals to them.

[rubocop-guide]: https://github.com/rubocop-hq/ruby-style-guide
