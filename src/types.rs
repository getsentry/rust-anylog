use std::borrow::Cow;
use chrono::prelude::*;

use parser;

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
}

#[test]
fn test_parse_short_log_entry() {
    let le = LogEntry::parse(b"Nov 20 21:56:01 herzog com.apple.xpc.launchd[1] (com.apple.preference.displays.MirrorDisplays): Service only ran for 0 seconds. Pushing respawn out by 10 seconds.");
    let dt = le.local_timestamp().unwrap();
    assert_eq!(dt.month(), 11);
    assert_eq!(dt.day(), 20);
    assert_eq!(dt.hour(), 21);
    assert_eq!(dt.minute(), 56);
    assert_eq!(dt.second(), 1);
    assert_eq!(le.message(), "herzog com.apple.xpc.launchd[1] (com.apple.preference.displays.MirrorDisplays): Service only ran for 0 seconds. Pushing respawn out by 10 seconds.");
}

#[test]
fn test_parse_short_log_entry_extra() {
    let le = LogEntry::parse(b"Mon Nov 20 00:31:19.005 <kernel> en0: Received EAPOL packet (length = 161)");
    let dt = le.local_timestamp().unwrap();
    assert_eq!(dt.month(), 11);
    assert_eq!(dt.day(), 20);
    assert_eq!(dt.hour(), 0);
    assert_eq!(dt.minute(), 31);
    assert_eq!(dt.second(), 19);
    assert_eq!(le.message(), "<kernel> en0: Received EAPOL packet (length = 161)");
}

#[test]
fn test_parse_simple_log_entry() {
    let le = LogEntry::parse(b"22:07:10 server  | detected binary path: /Users/mitsuhiko/.virtualenvs/sentry/bin/uwsgi");
    let dt = le.local_timestamp().unwrap();
    assert_eq!(dt.hour(), 22);
    assert_eq!(dt.minute(), 7);
    assert_eq!(dt.second(), 10);
    assert_eq!(le.message(), "server  | detected binary path: /Users/mitsuhiko/.virtualenvs/sentry/bin/uwsgi");
}

#[test]
fn test_parse_common_log_entry() {
    let le = LogEntry::parse(b"2015-05-13 17:39:16 +0200: Repaired 'Library/Printers/Canon/IJScanner/Resources/Parameters/CNQ9601'");
    let dt = le.utc_timestamp().unwrap();
    assert_eq!(dt.year(), 2015);
    assert_eq!(dt.month(), 5);
    assert_eq!(dt.day(), 13);
    assert_eq!(dt.hour(), 15);
    assert_eq!(dt.minute(), 39);
    assert_eq!(dt.second(), 16);
    assert_eq!(le.message(), "Repaired 'Library/Printers/Canon/IJScanner/Resources/Parameters/CNQ9601'");
}

#[test]
fn test_parse_common_alt_log_entry() {
    let le = LogEntry::parse(b"Mon Oct  5 11:40:10 2015	[INFO] PDApp.ExternalGateway - NativePlatformHandler destructed");
    let dt = le.local_timestamp().unwrap();
    assert_eq!(dt.year(), 2015);
    assert_eq!(dt.month(), 10);
    assert_eq!(dt.day(), 5);
    assert_eq!(dt.hour(), 11);
    assert_eq!(dt.minute(), 40);
    assert_eq!(dt.second(), 10);
    assert_eq!(le.message(), "[INFO] PDApp.ExternalGateway - NativePlatformHandler destructed");
}

#[test]
fn test_parse_common_alt2_log_entry() {
    let le = LogEntry::parse(b"Jan 03, 2016 22:29:55 [0x70000073b000] DEBUG - Responding HTTP/1.1 200");
    let dt = le.local_timestamp().unwrap();
    assert_eq!(dt.year(), 2016);
    assert_eq!(dt.month(), 1);
    assert_eq!(dt.day(), 3);
    assert_eq!(dt.hour(), 22);
    assert_eq!(dt.minute(), 29);
    assert_eq!(dt.second(), 55);
    assert_eq!(le.message(), "[0x70000073b000] DEBUG - Responding HTTP/1.1 200");
}
