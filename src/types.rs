use std::borrow::Cow;
use std::fmt;

use chrono::prelude::*;
use lazy_static::lazy_static;
use regex::Regex;

use crate::parser;

lazy_static! {
    static ref COMPONENT_RE: Regex = Regex::new(r#"^([^:]+): ?(.*)$"#).unwrap();
}

#[derive(Debug)]
pub enum Timestamp {
    Utc(DateTime<Utc>),
    Local(DateTime<Local>),
    Fixed(DateTime<FixedOffset>),
}

impl Timestamp {
    pub fn to_utc(&self) -> DateTime<Utc> {
        match *self {
            Timestamp::Utc(utc) => utc,
            Timestamp::Local(local) => local.with_timezone(&Utc),
            Timestamp::Fixed(fixed) => fixed.with_timezone(&Utc),
        }
    }

    pub fn to_local(&self) -> DateTime<Local> {
        match *self {
            Timestamp::Utc(utc) => utc.with_timezone(&Local),
            Timestamp::Local(local) => local,
            Timestamp::Fixed(fixed) => fixed.with_timezone(&Local),
        }
    }
}

/// Represents a parsed log entry.
pub struct LogEntry<'a> {
    timestamp: Option<Timestamp>,
    message: Cow<'a, str>,
}

impl<'a> fmt::Debug for LogEntry<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("LogEntry")
            .field("timestamp", &self.timestamp)
            .field("message", &self.message())
            .finish()
    }
}

impl<'a> LogEntry<'a> {
    /// Parses a well known log line into a log entry.
    pub fn parse(bytes: &[u8]) -> LogEntry {
        parser::parse_log_entry(bytes, None).unwrap_or_else(|| LogEntry::from_message_only(bytes))
    }

    /// Similar to `parse` but uses the given timezone for local time.
    pub fn parse_with_local_timezone(bytes: &[u8], offset: Option<FixedOffset>) -> LogEntry {
        parser::parse_log_entry(bytes, offset).unwrap_or_else(|| LogEntry::from_message_only(bytes))
    }

    /// Constructs a log entry from a UTC timestamp and message.
    pub fn from_utc_time(ts: DateTime<Utc>, message: &'a [u8]) -> LogEntry<'a> {
        LogEntry {
            timestamp: Some(Timestamp::Utc(ts)),
            message: String::from_utf8_lossy(message),
        }
    }

    /// Constructs a log entry from a local timestamp and message.
    pub fn from_local_time(ts: DateTime<Local>, message: &'a [u8]) -> LogEntry<'a> {
        LogEntry {
            timestamp: Some(Timestamp::Local(ts)),
            message: String::from_utf8_lossy(message),
        }
    }

    /// Constructs a log entry from a timestamp in a specific timezone and message.
    pub fn from_fixed_time(ts: DateTime<FixedOffset>, message: &'a [u8]) -> LogEntry<'a> {
        LogEntry {
            timestamp: Some(Timestamp::Fixed(ts)),
            message: String::from_utf8_lossy(message),
        }
    }

    /// Creates a log entry from only a message.
    pub fn from_message_only(message: &'a [u8]) -> LogEntry<'a> {
        LogEntry {
            timestamp: None,
            message: String::from_utf8_lossy(message),
        }
    }

    /// Returns the timestamp in local timezone.
    pub fn local_timestamp(&self) -> Option<DateTime<Local>> {
        self.timestamp.as_ref().map(|x| x.to_local())
    }

    /// Returns the timestamp in UTC timezone.
    pub fn utc_timestamp(&self) -> Option<DateTime<Utc>> {
        self.timestamp.as_ref().map(|x| x.to_utc())
    }

    /// Returns the message.
    pub fn message(&'a self) -> &str {
        &self.message
    }

    /// Like `message` but chops off a leading component.
    pub fn component_and_message(&'a self) -> (Option<&str>, &str) {
        if let Some(caps) = COMPONENT_RE.captures(&self.message()) {
            (
                Some(caps.get(1).unwrap().as_str()),
                caps.get(2).unwrap().as_str(),
            )
        } else {
            (None, self.message())
        }
    }
}

#[cfg(test)]
use insta::assert_debug_snapshot;

#[test]
fn test_parse_c_log_entry() {
    assert_debug_snapshot!(
    LogEntry::parse(b"Tue Nov 21 00:30:05 2017 More stuff here"),
        @r###"
    LogEntry {
        timestamp: Some(
            Local(
                2017-11-21T00:30:05+01:00,
            ),
        ),
        message: "More stuff here",
    }
    "###
    );
}

#[test]
fn test_parse_short_log_entry() {
    assert_debug_snapshot!(
    LogEntry::parse(b"Nov 20 21:56:01 herzog com.apple.xpc.launchd[1] (com.apple.preference.displays.MirrorDisplays): Service only ran for 0 seconds. Pushing respawn out by 10 seconds."),
        @r###"
    LogEntry {
        timestamp: Some(
            Local(
                2017-11-20T21:56:01+01:00,
            ),
        ),
        message: "herzog com.apple.xpc.launchd[1] (com.apple.preference.displays.MirrorDisplays): Service only ran for 0 seconds. Pushing respawn out by 10 seconds.",
    }
    "###
    );
}

#[test]
fn test_parse_short_log_entry_extra() {
    assert_debug_snapshot!(
    LogEntry::parse(
        b"Mon Nov 20 00:31:19.005 <kernel> en0: Received EAPOL packet (length = 161)",
    ),
        @r###"
    LogEntry {
        timestamp: Some(
            Local(
                2017-11-20T00:31:19+01:00,
            ),
        ),
        message: "<kernel> en0: Received EAPOL packet (length = 161)",
    }
    "###
    );
}

#[test]
fn test_parse_simple_log_entry() {
    assert_debug_snapshot!(
    LogEntry::parse(
        b"22:07:10 server  | detected binary path: /Users/mitsuhiko/.virtualenvs/sentry/bin/uwsgi",
    ),
        @r###"
    LogEntry {
        timestamp: Some(
            Local(
                2020-01-08T22:07:10+01:00,
            ),
        ),
        message: "server  | detected binary path: /Users/mitsuhiko/.virtualenvs/sentry/bin/uwsgi",
    }
    "###
    );
}

#[test]
fn test_parse_common_log_entry() {
    assert_debug_snapshot!(
        "common_log_entry",
        LogEntry::parse(b"2015-05-13 17:39:16 +0200: Repaired 'Library/Printers/Canon/IJScanner/Resources/Parameters/CNQ9601'")
    );
}

#[test]
fn test_parse_common_alt_log_entry() {
    assert_debug_snapshot!(
    LogEntry::parse(
        b"Mon Oct  5 11:40:10 2015	[INFO] PDApp.ExternalGateway - NativePlatformHandler destructed",
    ),
        @r###"
    LogEntry {
        timestamp: Some(
            Local(
                2015-10-05T11:40:10+02:00,
            ),
        ),
        message: "[INFO] PDApp.ExternalGateway - NativePlatformHandler destructed",
    }
    "###
    );
}

#[test]
fn test_parse_common_alt2_log_entry() {
    assert_debug_snapshot!(
    LogEntry::parse(b"Jan 03, 2016 22:29:55 [0x70000073b000] DEBUG - Responding HTTP/1.1 200"),
        @r###"
    LogEntry {
        timestamp: Some(
            Local(
                2016-01-03T22:29:55+01:00,
            ),
        ),
        message: "[0x70000073b000] DEBUG - Responding HTTP/1.1 200",
    }
    "###
    );
}

#[test]
fn test_parse_unreal_log_entry() {
    assert_debug_snapshot!(
    LogEntry::parse(
        b"[2018.10.29-16.56.37:542][  0]LogInit: Selected Device Profile: [WindowsNoEditor]",
    ),
        @r###"
    LogEntry {
        timestamp: Some(
            Utc(
                2018-10-29T16:56:37Z,
            ),
        ),
        message: "LogInit: Selected Device Profile: [WindowsNoEditor]",
    }
    "###
    );
}

#[test]
fn test_parse_unreal_log_entry_no_timestamp() {
    assert_debug_snapshot!(
    LogEntry::parse(
        b"LogDevObjectVersion:   Dev-Enterprise (9DFFBCD6-494F-0158-E221-12823C92A888): 1",
    ),
        @r###"
    LogEntry {
        timestamp: None,
        message: "LogDevObjectVersion:   Dev-Enterprise (9DFFBCD6-494F-0158-E221-12823C92A888): 1",
    }
    "###
    );
}

#[test]
fn test_simple_component_extraction() {
    assert_debug_snapshot!(
    LogEntry::parse(b"foo: bar").component_and_message(),
        @r###"
    (
        Some(
            "foo",
        ),
        "bar",
    )
    "###
    );
}
