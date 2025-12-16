# Lumberjack Gem Architecture

Lumberjack is a simple, powerful, and fast logging implementation in Ruby. It uses nearly the same API as the Logger class in the Ruby standard library and as ActiveSupport::BufferedLogger in Rails. The gem is designed with structured logging in mind, but can be used for simple text logging as well.

## Overview

The Lumberjack architecture follows a clean separation of concerns with the following main components:

- **Logger**: The main interface for creating log entries
- **LogEntry**: Data structure that captures log messages and metadata
- **Device**: Abstraction for different output destinations
- **Formatter**: Handles message formatting and transformation
- **TagFormatter**: Specialized formatting for tags
- **Template**: Template engine for customizing log output format
- **Context**: Thread-local context for managing tags across log entries
- **Severity**: Log level management and filtering

## Core Architecture

```mermaid
classDiagram
    class Logger {
        +Device device
        +Formatter formatter
        +TagFormatter tag_formatter
        +Integer level
        +String progname
        +Hash tags
        +initialize(device, options)
        +debug(message, progname, tags)
        +info(message, progname, tags)
        +warn(message, progname, tags)
        +error(message, progname, tags)
        +fatal(message, progname, tags)
        +add_entry(severity, message, progname, tags)
        +tag(tags_hash)
        +flush()
        +close()
    }

    class LogEntry {
        +Time time
        +Integer severity
        +Object message
        +String progname
        +Integer pid
        +Hash tags
        +initialize(time, severity, message, progname, pid, tags)
        +severity_label()
        +tag(name)
        +to_s()
    }

    class Device {
        <<abstract>>
        +write(entry)*
        +flush()
        +close()
        +reopen()
        +datetime_format()
        +datetime_format=(format)
    }

    class Formatter {
        +Hash class_formatters
        +Hash module_formatters
        +add(classes, formatter)
        +remove(classes)
        +format(message)
        +clear()
    }

    class TagFormatter {
        +Hash formatters
        +Object default_formatter
        +default(formatter)
        +add(names, formatter)
        +remove(names)
        +format(tags)
        +clear()
    }

    class Template {
        +String first_line_template
        +String additional_line_template
        +String datetime_format
        +compile(template)
        +call(entry)
        +datetime_format=(format)
    }

    class Context {
        +Hash tags
        +initialize(parent_context)
        +tag(tags)
        +\[](key)
        +\[]=(key, value)
        +reset()
    }

    class Severity {
        <<module>>
        +level_to_label(severity)
        +label_to_level(label)
        +coerce(value)
    }

    Logger --> LogEntry : creates
    Logger --> Device : writes to
    Logger --> Formatter : uses
    Logger --> TagFormatter : uses
    Logger --> Severity : includes
    Device --> Template : may use
    Formatter --> LogEntry : formats message
    TagFormatter --> LogEntry : formats tags
    Logger <-- Context : provides tags
```

## Device Hierarchy

The Device system provides a pluggable architecture for different output destinations:

```mermaid
classDiagram
    class Device {
        <<abstract>>
        +write(entry)*
        +flush()
        +close()
        +reopen()
    }

    class Writer {
        +IO stream
        +Template template
        +Buffer buffer
        +Integer buffer_size
        +write(entry)
        +flush()
        +before_flush()
    }

    class LogFile {
        +String file_path
        +write(entry)
        +reopen(file_path)
        +close()
    }

    class RollingLogFile {
        <<abstract>>
        +roll_file?()
        +roll_file!()
        +archive_file_suffix()
    }

    class DateRollingLogFile {
        +String roll
        +roll_file?()
        +archive_file_suffix()
    }

    class SizeRollingLogFile {
        +Integer max_size
        +Integer keep
        +roll_file?()
        +archive_file_suffix()
    }

    class Multi {
        +Array~Device~ devices
        +write(entry)
        +flush()
        +close()
    }

    class Null {
        +write(entry)
    }

    Device <|-- Writer
    Device <|-- Multi
    Device <|-- Null
    Writer <|-- LogFile
    LogFile <|-- RollingLogFile
    RollingLogFile <|-- DateRollingLogFile
    RollingLogFile <|-- SizeRollingLogFile
    Multi --> Device : contains multiple
```

## Data Flow

The logging process follows this flow:

```mermaid
sequenceDiagram
    participant Client
    participant Logger
    participant Formatter
    participant TagFormatter
    participant LogEntry
    participant Device
    participant Template

    Client->>Logger: info("message", tags: {key: value})
    Logger->>Logger: Check severity level
    Logger->>Formatter: format(message)
    Formatter-->>Logger: formatted_message
    Logger->>TagFormatter: format(tags)
    TagFormatter-->>Logger: formatted_tags
    Logger->>LogEntry: new(time, severity, message, progname, pid, tags)
    LogEntry-->>Logger: log_entry
    Logger->>Device: write(log_entry)
    Device->>Template: call(log_entry) [if Writer device]
    Template-->>Device: formatted_string
    Device->>Device: Write to output destination
```

## Key Features

### Thread Safety
- Logger operations are thread-safe
- Context provides thread-local tag storage
- Devices handle concurrent writes appropriately

### Structured Logging
- LogEntry captures structured data beyond just the message
- Tags provide key-value metadata
- Formatters can handle complex object serialization

### Pluggable Architecture
- Device abstraction allows custom output destinations
- Formatter system enables custom message transformation
- TagFormatter provides specialized tag handling

### Performance Optimization
- Buffered writing in Writer devices
- Lazy evaluation of expensive operations
- Configurable flush intervals

### ActiveSupport Compatibility
- TaggedLoggerSupport module provides Rails compatibility
- Compatible API with standard library Logger
- Supports ActiveSupport::TaggedLogging interface
