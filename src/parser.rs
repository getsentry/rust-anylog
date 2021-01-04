use std::str;

use chrono::prelude::*;
use lazy_static::lazy_static;
use regex::bytes::Regex;

use crate::types::LogEntry;

fn now() -> DateTime<Local> {
    #[cfg(test)]
    {
        Local.ymd(2017, 1, 1).and_hms(0, 0, 0)
    }
    #[cfg(not(test))]
    {
        Local::now()
    }
}

fn today(offset: Option<FixedOffset>) -> (i32, u32, u32) {
    match offset {
        None => {
            let today = {
                #[cfg(test)]
                {
                    Local.ymd(2017, 1, 1)
                }
                #[cfg(not(test))]
                {
                    Local::today()
                }
            };
            (today.year(), today.month(), today.day())
        }
        Some(offset) => {
            let today = {
                #[cfg(test)]
                {
                    Utc.ymd(2017, 1, 1)
                }
                #[cfg(not(test))]
                {
                    Utc::today()
                }
            }
            .with_timezone(&offset);
            (today.year(), today.month(), today.day())
        }
    }
}

lazy_static! {
    static ref C_LOG_RE: Regex = Regex::new(
        r#"(?x)
        ^
            \[?
            (?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\x20
            (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)
            \x20
            ([0-9]+)
            \x20
            ([0-9]{2}):([0-9]{2}):([0-9]{2})
            (?:\.[0-9]+)?
            \x20
            ([0-9]+)
            \]?
            [\t\x20]
            (.*)
        $
    "#
    ).unwrap();
    static ref SHORT_LOG_RE: Regex = Regex::new(
        r#"(?x)
        ^
            \[?
            (?:(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\x20)?
            (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)
            \x20
            ([0-9]+)
            \x20
            ([0-9]{2}):([0-9]{2}):([0-9]{2})
            (?:\.[0-9]+)?
            \]?
            [\t\x20]
            (.*)
        $
    "#
    ).unwrap();
    static ref SIMPLE_LOG_RE: Regex = Regex::new(
        r#"(?x)
        ^
            \[?
                ([0-9]+):
                ([0-9]+):
                ([0-9]+)
            \]?
            [\t\x20]
            (.*)
        $
    "#
    ).unwrap();
    static ref COMMON_LOG_RE: Regex = Regex::new(
        r#"(?x)
        ^
            \[?
            ([0-9]{4})-([0-9]{2})-([0-9]{2})
            \x20
            ([0-9]{2}):([0-9]{2}):([0-9]{2})
            \x20
            ([+-])
            ([0-9]{2})([0-9]{2})
            :?
            \]?
            [\t\x20]
            (.*)
        $
    "#
    ).unwrap();
    static ref COMMON_ALT_LOG_RE: Regex = Regex::new(
        r#"(?x)
        ^
            \[?
            (?:(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\x20)?
            (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)
            \x20+
            ([0-9]+)
            \x20
            ([0-9]{2}):([0-9]{2}):([0-9]{2})
            (?:\.[0-9]+)?
            \x20
            ([0-9]{4})
            \]?
            [\t\x20]
            (.*)
        $
    "#
    ).unwrap();
    static ref COMMON_ALT2_LOG_RE: Regex = Regex::new(
        r#"(?x)
        ^
            \[?
            (?:(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\x20)?
            (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)
            \x20+
            ([0-9]+),?
            \x20
            ([0-9]{4})
            \x20
            ([0-9]{2}):([0-9]{2}):([0-9]{2})
            (?:\.[0-9]+)?
            \]?
            [\t\x20]
            (.*)
        $
    "#
    ).unwrap();
    static ref UE4_LOG_RE: Regex = Regex::new(
        // [2018.10.29-16.56.37:542][  0]LogInit: Selected Device Profile: [WindowsNoEditor]
        r#"(?x)
        ^
            \[
                ([0-9]+)\.([0-9]+)\.([0-9]+)
                -
                ([0-9]+)\.([0-9]+)\.([0-9]+)
                :
                (?:[0-9]+)
            \]
            \[\x20+[0-9]+\]
            (.*)
        $
    "#
    ).unwrap();
}

macro_rules! log_entry_from_local_time {
    ($offset:expr, $y:expr, $m:expr, $d:expr, $hh:expr, $mm:expr, $ss:expr, $msg:expr) => {
        match $offset {
            Some(offset) => offset
                .ymd($y, $m, $d)
                .and_hms_opt($hh, $mm, $ss)
                .map(|date| LogEntry::from_fixed_time(date, $msg)),
            None => Local
                .ymd($y, $m, $d)
                .and_hms_opt($hh, $mm, $ss)
                .map(|date| LogEntry::from_local_time(date, $msg)),
        }
    };
}

fn get_month(bytes: &[u8]) -> Option<u32> {
    Some(match bytes {
        b"Jan" => 1,
        b"Feb" => 2,
        b"Mar" => 3,
        b"Apr" => 4,
        b"May" => 5,
        b"Jun" => 6,
        b"Jul" => 7,
        b"Aug" => 8,
        b"Sep" => 9,
        b"Oct" => 10,
        b"Nov" => 11,
        b"Dec" => 12,
        _ => return None,
    })
}

pub fn parse_c_log_entry(bytes: &[u8], offset: Option<FixedOffset>) -> Option<LogEntry> {
    let caps = match C_LOG_RE.captures(bytes) {
        Some(caps) => caps,
        None => return None,
    };

    let month = get_month(&caps[1]).unwrap();
    let day: u32 = str::from_utf8(&caps[2]).unwrap().parse().unwrap();
    let h: u32 = str::from_utf8(&caps[3]).unwrap().parse().unwrap();
    let m: u32 = str::from_utf8(&caps[4]).unwrap().parse().unwrap();
    let s: u32 = str::from_utf8(&caps[5]).unwrap().parse().unwrap();
    let year: i32 = str::from_utf8(&caps[6]).unwrap().parse().unwrap();

    log_entry_from_local_time!(
        offset,
        year,
        month,
        day,
        h,
        m,
        s,
        caps.get(7).map(|x| x.as_bytes()).unwrap()
    )
}

pub fn parse_short_log_entry(bytes: &[u8], offset: Option<FixedOffset>) -> Option<LogEntry> {
    let caps = match SHORT_LOG_RE.captures(bytes) {
        Some(caps) => caps,
        None => return None,
    };

    let year = now().year();
    let month = get_month(&caps[1]).unwrap();
    let day: u32 = str::from_utf8(&caps[2]).unwrap().parse().unwrap();
    let h: u32 = str::from_utf8(&caps[3]).unwrap().parse().unwrap();
    let m: u32 = str::from_utf8(&caps[4]).unwrap().parse().unwrap();
    let s: u32 = str::from_utf8(&caps[5]).unwrap().parse().unwrap();

    log_entry_from_local_time!(
        offset,
        year,
        month,
        day,
        h,
        m,
        s,
        caps.get(6).map(|x| x.as_bytes()).unwrap()
    )
}

pub fn parse_simple_log_entry(bytes: &[u8], offset: Option<FixedOffset>) -> Option<LogEntry> {
    let caps = match SIMPLE_LOG_RE.captures(bytes) {
        Some(caps) => caps,
        None => return None,
    };

    let h: u32 = str::from_utf8(&caps[1]).unwrap().parse().unwrap();
    let m: u32 = str::from_utf8(&caps[2]).unwrap().parse().unwrap();
    let s: u32 = str::from_utf8(&caps[3]).unwrap().parse().unwrap();

    let (year, month, day) = today(offset);
    log_entry_from_local_time!(
        offset,
        year,
        month,
        day,
        h,
        m,
        s,
        caps.get(4).map(|x| x.as_bytes()).unwrap()
    )
}

pub fn parse_common_log_entry(bytes: &[u8], _offset: Option<FixedOffset>) -> Option<LogEntry> {
    let caps = match COMMON_LOG_RE.captures(bytes) {
        Some(caps) => caps,
        None => return None,
    };

    let year: i32 = str::from_utf8(&caps[1]).unwrap().parse().unwrap();
    let month: u32 = str::from_utf8(&caps[2]).unwrap().parse().unwrap();
    let day: u32 = str::from_utf8(&caps[3]).unwrap().parse().unwrap();
    let h: u32 = str::from_utf8(&caps[4]).unwrap().parse().unwrap();
    let m: u32 = str::from_utf8(&caps[5]).unwrap().parse().unwrap();
    let s: u32 = str::from_utf8(&caps[6]).unwrap().parse().unwrap();

    let offset = FixedOffset::east(
        ((if &caps[7] == b"+" { 1i32 } else { -1i32 })
            * str::from_utf8(&caps[8]).unwrap().parse::<i32>().unwrap()
            * 60
            + str::from_utf8(&caps[9]).unwrap().parse::<i32>().unwrap())
            * 60,
    );

    Some(LogEntry::from_fixed_time(
        offset.ymd(year, month, day).and_hms(h, m, s),
        caps.get(10).map(|x| x.as_bytes()).unwrap(),
    ))
}

pub fn parse_common_alt_log_entry(bytes: &[u8], offset: Option<FixedOffset>) -> Option<LogEntry> {
    let caps = match COMMON_ALT_LOG_RE.captures(bytes) {
        Some(caps) => caps,
        None => return None,
    };

    let month = get_month(&caps[1]).unwrap();
    let day: u32 = str::from_utf8(&caps[2]).unwrap().parse().unwrap();
    let h: u32 = str::from_utf8(&caps[3]).unwrap().parse().unwrap();
    let m: u32 = str::from_utf8(&caps[4]).unwrap().parse().unwrap();
    let s: u32 = str::from_utf8(&caps[5]).unwrap().parse().unwrap();
    let year: i32 = str::from_utf8(&caps[6]).unwrap().parse().unwrap();

    log_entry_from_local_time!(
        offset,
        year,
        month,
        day,
        h,
        m,
        s,
        caps.get(7).map(|x| x.as_bytes()).unwrap()
    )
}

pub fn parse_common_alt2_log_entry(bytes: &[u8], offset: Option<FixedOffset>) -> Option<LogEntry> {
    let caps = match COMMON_ALT2_LOG_RE.captures(bytes) {
        Some(caps) => caps,
        None => return None,
    };

    let month = get_month(&caps[1]).unwrap();
    let day: u32 = str::from_utf8(&caps[2]).unwrap().parse().unwrap();
    let year: i32 = str::from_utf8(&caps[3]).unwrap().parse().unwrap();
    let h: u32 = str::from_utf8(&caps[4]).unwrap().parse().unwrap();
    let m: u32 = str::from_utf8(&caps[5]).unwrap().parse().unwrap();
    let s: u32 = str::from_utf8(&caps[6]).unwrap().parse().unwrap();

    log_entry_from_local_time!(
        offset,
        year,
        month,
        day,
        h,
        m,
        s,
        caps.get(7).map(|x| x.as_bytes()).unwrap()
    )
}

pub fn parse_ue4_log_entry(bytes: &[u8], _offset: Option<FixedOffset>) -> Option<LogEntry> {
    let caps = match UE4_LOG_RE.captures(bytes) {
        Some(caps) => caps,
        None => return None,
    };

    let year: i32 = str::from_utf8(&caps[1]).unwrap().parse().unwrap();
    let month: u32 = str::from_utf8(&caps[2]).unwrap().parse().unwrap();
    let day: u32 = str::from_utf8(&caps[3]).unwrap().parse().unwrap();
    let h: u32 = str::from_utf8(&caps[4]).unwrap().parse().unwrap();
    let m: u32 = str::from_utf8(&caps[5]).unwrap().parse().unwrap();
    let s: u32 = str::from_utf8(&caps[6]).unwrap().parse().unwrap();

    Some(LogEntry::from_utc_time(
        Utc.ymd(year, month, day).and_hms(h, m, s),
        caps.get(7).map(|x| x.as_bytes()).unwrap(),
    ))
}

pub fn parse_log_entry(bytes: &[u8], offset: Option<FixedOffset>) -> Option<LogEntry> {
    macro_rules! attempt {
        ($func:ident) => {
            if let Some(rv) = $func(bytes, offset) {
                return Some(rv);
            }
        };
    }

    attempt!(parse_c_log_entry);
    attempt!(parse_short_log_entry);
    attempt!(parse_simple_log_entry);
    attempt!(parse_common_log_entry);
    attempt!(parse_common_alt_log_entry);
    attempt!(parse_common_alt2_log_entry);
    attempt!(parse_ue4_log_entry);

    None
}

#[cfg(test)]
use insta::assert_debug_snapshot;

#[test]
fn test_parse_c_log_entry() {
    assert_debug_snapshot!(
        parse_c_log_entry(b"Tue Nov 21 00:30:05 2017 More stuff here", None),
        @r###"
        Some(
            LogEntry {
                timestamp: Some(
                    Local(
                        2017-11-21T00:30:05+01:00,
                    ),
                ),
                message: "More stuff here",
            },
        )
        "###
    );
}

#[test]
fn test_parse_short_log_entry() {
    assert_debug_snapshot!(
        parse_short_log_entry(
            b"Nov 20 21:56:01 herzog com.apple.xpc.launchd[1] (com.apple.preference.displays.MirrorDisplays): Service only ran for 0 seconds. Pushing respawn out by 10 seconds.",
            None
        ),
        @r###"
        Some(
            LogEntry {
                timestamp: Some(
                    Local(
                        2017-11-20T21:56:01+01:00,
                    ),
                ),
                message: "herzog com.apple.xpc.launchd[1] (com.apple.preference.displays.MirrorDisplays): Service only ran for 0 seconds. Pushing respawn out by 10 seconds.",
            },
        )
        "###
    );
}

#[test]
fn test_parse_short_log_entry_extra() {
    assert_debug_snapshot!(
        parse_short_log_entry(
            b"Mon Nov 20 00:31:19.005 <kernel> en0: Received EAPOL packet (length = 161)",
            None
        ),
        @r###"
        Some(
            LogEntry {
                timestamp: Some(
                    Local(
                        2017-11-20T00:31:19+01:00,
                    ),
                ),
                message: "<kernel> en0: Received EAPOL packet (length = 161)",
            },
        )
        "###
    );
}

#[test]
fn test_parse_simple_log_entry() {
    assert_debug_snapshot!(
        parse_simple_log_entry(
            b"22:07:10 server  | detected binary path: /Users/mitsuhiko/.virtualenvs/sentry/bin/uwsgi",
            None
        ),
        @r###"
        Some(
            LogEntry {
                timestamp: Some(
                    Local(
                        2017-01-01T22:07:10+01:00,
                    ),
                ),
                message: "server  | detected binary path: /Users/mitsuhiko/.virtualenvs/sentry/bin/uwsgi",
            },
        )
        "###
    );
}

#[test]
fn test_parse_common_log_entry() {
    assert_debug_snapshot!(
        parse_common_log_entry(
            b"2015-05-13 17:39:16 +0200: Repaired 'Library/Printers/Canon/IJScanner/Resources/Parameters/CNQ9601'",
            None
        ),
        @r###"
        Some(
            LogEntry {
                timestamp: Some(
                    Fixed(
                        2015-05-13T17:39:16+02:00,
                    ),
                ),
                message: "Repaired \'Library/Printers/Canon/IJScanner/Resources/Parameters/CNQ9601\'",
            },
        )
        "###
    );
}

#[test]
fn test_parse_common_alt_log_entry() {
    assert_debug_snapshot!(
        parse_common_alt_log_entry(
            b"Mon Oct  5 11:40:10 2015	[INFO] PDApp.ExternalGateway - NativePlatformHandler destructed",
            None
        ),
        @r###"
        Some(
            LogEntry {
                timestamp: Some(
                    Local(
                        2015-10-05T11:40:10+02:00,
                    ),
                ),
                message: "[INFO] PDApp.ExternalGateway - NativePlatformHandler destructed",
            },
        )
        "###
    );
}

#[test]
fn test_parse_common_alt2_log_entry() {
    assert_debug_snapshot!(
        parse_common_alt2_log_entry(
            b"Jan 03, 2016 22:29:55 [0x70000073b000] DEBUG - Responding HTTP/1.1 200",
            None
        ),
        @r###"
        Some(
            LogEntry {
                timestamp: Some(
                    Local(
                        2016-01-03T22:29:55+01:00,
                    ),
                ),
                message: "[0x70000073b000] DEBUG - Responding HTTP/1.1 200",
            },
        )
        "###
    );
}

#[test]
fn test_parse_webserver_log() {
    assert_debug_snapshot!(
        parse_common_alt_log_entry(b"[Sun Feb 25 06:11:12.043123448 2018] [:notice] [pid 1:tid 2] process manager initialized (pid 1)", None),
        @r###"
        Some(
            LogEntry {
                timestamp: Some(
                    Local(
                        2018-02-25T06:11:12+01:00,
                    ),
                ),
                message: "[:notice] [pid 1:tid 2] process manager initialized (pid 1)",
            },
        )
        "###
    )
}

#[test]
fn test_parse_invalid_time() {
    // same as test_parse_c_log_entry, except for invalid timestamp
    assert_debug_snapshot!(
        parse_c_log_entry(b"Tue Nov 21 99:99:99 2017 More stuff here", None),
        @"None"
    );
}
