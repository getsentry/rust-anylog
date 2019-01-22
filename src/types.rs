use std::borrow::Cow;
use std::fmt;

use chrono::prelude::*;
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

pub struct LogEntry<'a> {
    timestamp: Option<Timestamp>,
    message: &'a [u8],
}

impl<'a> fmt::Debug for LogEntry<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("LogEntry")
            .field("utc_timestamp", &self.utc_timestamp())
            .field("message", &self.message())
            .finish()
    }
}

impl<'a> LogEntry<'a> {
    pub fn from_utc_time(ts: DateTime<Utc>, message: &'a [u8]) -> LogEntry<'a> {
        LogEntry {
            timestamp: Some(Timestamp::Utc(ts)),
            message: message,
        }
    }

    pub fn from_local_time(ts: DateTime<Local>, message: &'a [u8]) -> LogEntry<'a> {
        LogEntry {
            timestamp: Some(Timestamp::Local(ts)),
            message: message,
        }
    }

    pub fn from_fixed_time(ts: DateTime<FixedOffset>, message: &'a [u8]) -> LogEntry<'a> {
        LogEntry {
            timestamp: Some(Timestamp::Fixed(ts)),
            message: message,
        }
    }

    pub fn from_message_only(message: &'a [u8]) -> LogEntry<'a> {
        LogEntry {
            timestamp: None,
            message: message,
        }
    }

    pub fn parse(bytes: &[u8]) -> LogEntry {
        parser::parse_log_entry(bytes).unwrap_or_else(|| LogEntry::from_message_only(bytes))
    }

    pub fn local_timestamp(&self) -> Option<DateTime<Local>> {
        self.timestamp.as_ref().map(|x| x.to_local())
    }

    pub fn utc_timestamp(&self) -> Option<DateTime<Utc>> {
        self.timestamp.as_ref().map(|x| x.to_utc())
    }

    pub fn message(&'a self) -> Cow<'a, str> {
        String::from_utf8_lossy(self.message)
    }

    pub fn component_and_message(&'a self) -> (Option<String>, String) {
        if let Some(caps) = COMPONENT_RE.captures(&self.message()) {
            (Some(caps[1].to_string()), caps[2].to_string())
        } else {
            (None, self.message().to_string())
        }
    }
}

#[cfg(test)]
use insta::assert_debug_snapshot_matches;

#[test]
fn test_parse_c_log_entry() {
    assert_debug_snapshot_matches!(
        "c_log_entry",
        LogEntry::parse(b"Tue Nov 21 00:30:05 2017 More stuff here")
    );
}

#[test]
fn test_parse_short_log_entry() {
    assert_debug_snapshot_matches!("short_log_entry", LogEntry::parse(b"Nov 20 21:56:01 herzog com.apple.xpc.launchd[1] (com.apple.preference.displays.MirrorDisplays): Service only ran for 0 seconds. Pushing respawn out by 10 seconds."));
}

#[test]
fn test_parse_short_log_entry_extra() {
    assert_debug_snapshot_matches!(
        "short_log_entry_extra",
        LogEntry::parse(
            b"Mon Nov 20 00:31:19.005 <kernel> en0: Received EAPOL packet (length = 161)",
        )
    );
}

#[test]
fn test_parse_simple_log_entry() {
    assert_debug_snapshot_matches!(
        "simple_log_entry", LogEntry::parse(
            b"22:07:10 server  | detected binary path: /Users/mitsuhiko/.virtualenvs/sentry/bin/uwsgi",
        )
    );
}

#[test]
fn test_parse_common_log_entry() {
    assert_debug_snapshot_matches!(
        "common_log_entry",
        LogEntry::parse(b"2015-05-13 17:39:16 +0200: Repaired 'Library/Printers/Canon/IJScanner/Resources/Parameters/CNQ9601'")
    );
}

#[test]
fn test_parse_common_alt_log_entry() {
    assert_debug_snapshot_matches!(
        "common_alt_log_entry",
        LogEntry::parse(
            b"Mon Oct  5 11:40:10 2015	[INFO] PDApp.ExternalGateway - NativePlatformHandler destructed",
        )
    );
}

#[test]
fn test_parse_common_alt2_log_entry() {
    assert_debug_snapshot_matches!(
        "common_alt2_log_entry",
        LogEntry::parse(b"Jan 03, 2016 22:29:55 [0x70000073b000] DEBUG - Responding HTTP/1.1 200")
    );
}

#[test]
fn test_parse_unreal_log_entry() {
    assert_debug_snapshot_matches!(
        "unreal_log_entry",
        LogEntry::parse(
            b"[2018.10.29-16.56.37:542][  0]LogInit: Selected Device Profile: [WindowsNoEditor]",
        )
    );
}

#[test]
fn test_parse_unreal_log_entry_no_timestamp() {
    assert_debug_snapshot_matches!(
        "unreal_log_entry_no_timestamp",
        LogEntry::parse(
            b"LogDevObjectVersion:   Dev-Enterprise (9DFFBCD6-494F-0158-E221-12823C92A888): 1",
        )
    );
}
