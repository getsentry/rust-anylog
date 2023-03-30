# rust-anylog

A simple rust library that parses log lines into log records.  This supports a range
of common log formats and parses out the timestamp and rest of the line.

[Documentation](https://docs.rs/anylog)

## Tests

Tests require the timezone to be set to "CEST". The easiest way to do this is by
exporting the `TZ` environment variable:

```bash
TZ=CET cargo test
```
