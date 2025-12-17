# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 1.4.2

### Fixed

- Fixed issue where calling `Lumberjack::LogEntry#tag` would raise an error if there were no tags set on the log entry.

## 1.4.1

### Changed

- Catch errors when formatting values so that it doesn't prevent logging. Otherwise there can be no way to log that the error occurred. Values that produced errors in the formatter will now be shown in the logs as "<Error formatting CLASS_NAME: ERROR_CLASS ERROR_MESSAGE>".

## 1.4.0

### Changed

- Tags are consistently flattened internally to dot notation keys. This makes tag handling more consistent when using nested hashes as tag values. This changes how nested tags are merged, though. Now when new nested tags are set they will be merged into the existing tags rather than replacing them entirely. So `logger.tag(foo: {bar: "baz"})` will now merge the `foo.bar` tag into the existing tags rather than replacing the entire `foo` tag.
- The `Lumberjack::Logger#context` method can now be called without a block. When called with a block it sets up a new tag context for the block. When called without a block, it returns the current tag context in a `Lumberjack::TagContext` object which can be used to add tags to the current context.
- Tags in `Lumberjack::LogEntry` are now always stored as a hash of flattened keys. This means that when tags are set on a log entry, they will be automatically flattened to dot notation keys. The `tag` method will return a hash of sub-tags if the tag name is a tag prefix.

### Added

- Added `Lumberjack::LogEntry#nested_tags` method to return the tags as a nested hash structure.

## 1.3.4

### Added

- Added `Lumberjack::Logger#with_progname` alias for `set_progname` to match the naming convention used for setting temporary levels.

### Fixed

- Ensure that the safety check for circular calls to `Lumberjack::Logger#add_entry` cannot lose state.

## 1.3.3

### Added

- Added `Lumberjack::Utils#expand_tags` method to expand a hash of tags that may contain nested hashes or dot notation keys.

### Changed

- Updated `Lumberjack::Utils#flatten_tags` to convert all keys to strings.

## 1.3.2

### Fixed

- Fixed `NoMethodError` when setting the device via the `Lumberjack::Logger#device=` method.

## 1.3.1

### Added

- Added `Lumberjack::Logger#context` method to set up a context block for the logger. This is the same as calling `Lumberjack::Logger#tag` with an empty hash.
- Log entries now remove empty tag values so they don't have to be removed downstream.

### Fixed

- ActiveSupport::TaggedLogger now calls `Lumberjack::Logger#tag_globally` to prevent deprecation warnings.

## 1.3.0

### Added

- Added `Lumberjack::Formatter::TaggedMessage` to allow extracting tags from log messages via a formatter in order to better support structured logging of objects.
- Added built in `:round` formatter to round numbers to a specified number of decimal places.
- Added built in `:redact` formatter to redact sensitive information from log tags.
- Added support in `Lumberjack::TagFormatter` for class formatters. Class formatters will be applied to any tag values that match the class.
- Apply formatters to enumerable values in tags. Name formatters are applied using dot syntax when a tag value contains a hash.
- Added support for a dedicated message formatter that can override the default formatter on the log message.
- Added support for setting tags from the request environment in `Lumberjack::Rack::Context` middleware.
- Added helper methods to generate global PID's and thread ids.
- Added `Lumberjack::Logger#tag_globally` to explicitly set a global tag for all loggers.
- Added `Lumberjack::Logger#tag_value` to get the value of a tag by name from the current tag context.
- Added `Lumberjack::Utils.hostname` to get the hostname in UTF-8 encoding.
- Added `Lumberjack::Utils.global_pid` to get a global process id in a consistent format.
- Added `Lumberjack::Utils.global_thread_id` to get a thread id in a consistent format.
- Added `Lumberjack::Utils.thread_name` to get a thread name in a consistent format.
- Added support for `ActiveSupport::Logging.logger_outputs_to?` to check if a logger is outputting to a specific IO stream.
- Added `Lumberjack::Logger#log_at` method to temporarily set the log level for a block of code for compatibility with ActiveSupport loggers.

### Changed

- Default date/time format for log entries is now ISO-8601 with microsecond precision.
- Tags that are set to hash values will now be flattened into dot-separated keys in templates.

### Removed

- Removed support for Ruby versions < 2.5.

### Deprecated

- All unit of work related functionality from version 1.0 has been officially deprecated and will be removed in version 2.0. Use tags instead to set a global context for log entries.
- Calling `Lumberjack::Logger#tag` without a block is deprecated. Use `Lumberjack::Logger#tag_globally` instead.

## 1.2.10

### Added

- Added `with_level` method for compatibility with the latest standard library logger gem.

### Fixed

- Fixed typo in magic frozen string literal comments. (thanks @andyw8 and @steveclarke)

## 1.2.9

### Added

- Allow passing in formatters as class names when adding them.
- Allow passing in formatters initialization arguments when adding them.
- Add truncate formatter for capping the length of log messages.

## 1.2.8

### Added

- Add `Logger#untagged` to remove previously set logging tags from a block.
- Return result of the block when a block is passed to `Logger#tag`.

## 1.2.7

### Fixed

- Allow passing frozen hashes to `Logger#tag`. Tags passed to this method are now duplicated so the logger maintains it's own copy of the hash.

## 1.2.6

### Added

- Add Logger#remove_tag

### Fixed

- Fix `Logger#tag` so it only ads to the current block's logger tags instead of the global tags if called inside a `Logger#tag` block.


## 1.2.5

### Added

- Add support for bang methods (error!) for setting the log level.

### Fixed

- Fixed logic with recursive reference guard in StructuredFormatter so it only suppresses Enumerable references.

## 1.2.4

### Added

- Enhance `ActiveSupport::TaggedLogging` support so code that Lumberjack loggers can be wrapped with a tagged logger.

## 1.2.3

### Fixed

- Fix structured formatter so no-recursive, duplicate references are allowed.

## 1.2.2

### Fixed

- Prevent infinite loops in the structured formatter where objects have backreferences to each other.

## 1.2.1

### Fixed

- Prevent infinite loops where logging a statement triggers the logger.

## 1.2.0

### Added

- Enable compatibility with `ActiveSupport::TaggedLogger` by calling `tagged_logger!` on a logger.
- Add `tag_formatter` to logger to specify formatting of tags for output.
- Allow adding and removing classes by name to formatters.
- Allow adding and removing multiple classes in a single call to a formatter.
- Allow using symbols and strings as log level for silencing a logger.
- Ensure flusher thread gets stopped when logger is closed.
- Add writer for logger device attribute.
- Handle passing an array of devices to a multi device.
- Helper method to get a tag with a specified name.
- Add strip formatter to strip whitespace from strings.
- Support non-alpha numeric characters in template variables.
- Add backtrace cleaner to ExceptionFormatter.

## 1.1.1

### Added

- Replace Procs in tag values with the value of calling the Proc in log entries.

## 1.1.0

### Added

- Change `Lumberjack::Logger` to inherit from ::Logger
- Add support for tags on log messages
- Add global tag context for all loggers
- Add per logger tags and tag contexts
- Reimplement unit of work id as a tag on log entries
- Add support for setting datetime format on log devices
- Performance optimizations
- Add Multi device to output to multiple devices
- Add `DateTimeFormatter`, `IdFormatter`, `ObjectFormatter`, and `StructuredFormatter`
- Add rack `Context` middleware for setting thread global context
- Add support for modules in formatters

### Removed

- End support for ruby versions < 2.3

## 1.0.13

### Added

- Added `:min_roll_check` option to `Lumberjack::Device::RollingLogFile` to reduce file system checks. Default is now to only check if a file needs to be rolled at most once per second.
- Force immutable strings for Ruby versions that support them.

### Changed

- Reduce amount of code executed inside a mutex lock when writing to the logger stream.

## 1.0.12

### Added

- Add support for `ActionDispatch` request id for better Rails compatibility.

## 1.0.11

### Fixed

- Fix Ruby 2.4 deprecation warning on Fixnum (thanks @koic).
- Fix gemspec files to be flat array (thanks @e2).

## 1.0.10

### Added

- Expose option to manually roll log files.

### Changed

- Minor code cleanup.

## 1.0.9

### Added

- Add method so Formatter is compatible with `ActiveSupport` logging extensions.

## 1.0.8

### Fixed

- Fix another internal variable name conflict with `ActiveSupport` logging extensions.

## 1.0.7

### Fixed

- Fix broken formatter attribute method.

## 1.0.6

### Fixed

- Fix internal variable name conflict with `ActiveSupport` logging extensions.

## 1.0.5

### Changed

- Update docs.
- Remove autoload calls to make thread safe.
- Make compatible with Ruby 2.1.1 Pathname.
- Make compatible with standard library Logger's use of progname as default message.

## 1.0.4

### Added

- Add ability to supply a unit of work id for a block instead of having one generated every time.

## 1.0.3

### Fixed

- Change log file output format to binary to avoid encoding warnings.
- Fixed bug in log file rolling that left the file locked.

## 1.0.2

### Fixed

- Remove deprecation warnings under ruby 1.9.3.
- Add more error checking around file rolling.

## 1.0.1

### Fixed

- Writes are no longer buffered by default.

## 1.0.0

### Added

- Initial release
