# RuboCop GitHub

[![test](https://github.com/github/rubocop-github/actions/workflows/test.yml/badge.svg)](https://github.com/github/rubocop-github/actions/workflows/test.yml)
[![build](https://github.com/github/rubocop-github/actions/workflows/build.yml/badge.svg)](https://github.com/github/rubocop-github/actions/workflows/build.yml)
[![lint](https://github.com/github/rubocop-github/actions/workflows/lint.yml/badge.svg)](https://github.com/github/rubocop-github/actions/workflows/lint.yml)
[![release](https://github.com/github/rubocop-github/actions/workflows/release.yml/badge.svg)](https://github.com/github/rubocop-github/actions/workflows/release.yml)

This repository provides recommended RuboCop configuration and additional Cops for use on GitHub open source and internal Ruby projects, and is the home of [GitHub's Ruby Style Guide](./STYLEGUIDE.md).

## Usage

Add `rubocop-github` to your Gemfile, along with its dependencies:

  ```ruby
  gem "rubocop-github", require: false
  gem "rubocop-performance", require: false
  gem "rubocop-rails", require: false
  ```

Inherit all of the stylistic rules and cops through an inheritance declaration in your `.rubocop.yml`:

  ```yaml
  # .rubocop.yml
  inherit_gem:
    rubocop-github:
    - config/default.yml # generic Ruby rules and cops
    - config/rails.yml # Rails-specific rules and cops
  ```

Alternatively, only require the additional custom cops in your `.rubocop.yml` without inheriting/enabling the other stylistic rules:

  ```yaml
  # .rubocop.yml
  require:
    - rubocop-github  # generic Ruby cops only
    - rubocop-github-rails # Rails-specific cops only
  ```

💭 Looking for `config/accessibility.yml` and the `GitHub/Accessibility` configs? They have been moved to [a new gem](https://github.com/github/rubocop-rails-accessibility).

For more granular control over which of RuboCop's rules are enabled for your project, both from this gem and your own configs, consider using the `DisabledByDefault: true` option under `AllCops` in your project's `.rubocop.yml` file. This will disable all cops by default, and you can then explicitly enable the ones you want by setting `Enabled: true`. See [the RuboCop docs](https://docs.rubocop.org/rubocop/configuration.html#enabled) for more information.

### Legacy usage

If you are using a rubocop version < 1.0.0, you can use rubocop-github version
0.16.2 (see the README from that version for more details).

## Testing

``` bash
bundle install
bundle exec rake test
```

## The Cops

All cops are located under [`lib/rubocop/cop/github`](lib/rubocop/cop/github).
