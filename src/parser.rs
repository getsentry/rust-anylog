use chrono::prelude::*;
use regex::bytes::Regex;
use std::str;

use types::LogEntry;

lazy_static! {
    static ref C_LOG_RE: Regex = Regex::new(
        r#"(?x)
        ^
            \[?
            (?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\x20
            (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)
            \x20
            (\d+)
            \x20
            (\d{2}):(\d{2}):(\d{2})
            (?:\.\d+)?
            \x20
            (\d+)
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
            (\d+)
            \x20
            (\d{2}):(\d{2}):(\d{2})
            (?:\.\d+)?
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
                (\d+):
                (\d+):
                (\d+)
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
            (\d{4})-(\d{2})-(\d{2})
            \x20
            (\d{2}):(\d{2}):(\d{2})
            \x20
            ([+-])
            (\d{2})(\d{2})
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
            (\d+)
            \x20
            (\d{2}):(\d{2}):(\d{2})
            (?:\.\d+)?
            \x20
            (\d{4})
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
            (\d+),?
            \x20
            (\d{4})
            \x20
            (\d{2}):(\d{2}):(\d{2})
            (?:\.\d+)?
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
                (\d+)\.(\d+)\.(\d+)
                -
                (\d+)\.(\d+)\.(\d+)
                :
                (?:\d+)
            \]
            \[\x20+\d+\]
            (.*)
        $
    "#
    ).unwrap();
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

pub fn parse_c_log_entry(bytes: &[u8]) -> Option<LogEntry> {
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

    Some(LogEntry::from_local_time(
        Local.ymd(year, month, day).and_hms(h, m, s),
        caps.get(7).map(|x| x.as_bytes()).unwrap(),
    ))
}

pub fn parse_short_log_entry(bytes: &[u8]) -> Option<LogEntry> {
    let caps = match SHORT_LOG_RE.captures(bytes) {
        Some(caps) => caps,
        None => return None,
    };

    let year = Local::now().year();
    let month = get_month(&caps[1]).unwrap();
    let day: u32 = str::from_utf8(&caps[2]).unwrap().parse().unwrap();
    let h: u32 = str::from_utf8(&caps[3]).unwrap().parse().unwrap();
    let m: u32 = str::from_utf8(&caps[4]).unwrap().parse().unwrap();
    let s: u32 = str::from_utf8(&caps[5]).unwrap().parse().unwrap();

    Some(LogEntry::from_local_time(
        Local.ymd(year, month, day).and_hms(h, m, s),
        caps.get(6).map(|x| x.as_bytes()).unwrap(),
    ))
}

pub fn parse_simple_log_entry(bytes: &[u8]) -> Option<LogEntry> {
    let caps = match SIMPLE_LOG_RE.captures(bytes) {
        Some(caps) => caps,
        None => return None,
    };

    let h: u32 = str::from_utf8(&caps[1]).unwrap().parse().unwrap();
    let m: u32 = str::from_utf8(&caps[2]).unwrap().parse().unwrap();
    let s: u32 = str::from_utf8(&caps[3]).unwrap().parse().unwrap();

    Some(LogEntry::from_local_time(
        Local::today().and_hms(h, m, s),
        caps.get(4).map(|x| x.as_bytes()).unwrap(),
    ))
}

pub fn parse_common_log_entry(bytes: &[u8]) -> Option<LogEntry> {
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

pub fn parse_common_alt_log_entry(bytes: &[u8]) -> Option<LogEntry> {
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

    Some(LogEntry::from_local_time(
        Local.ymd(year, month, day).and_hms(h, m, s),
        caps.get(7).map(|x| x.as_bytes()).unwrap(),
    ))
}

pub fn parse_common_alt2_log_entry(bytes: &[u8]) -> Option<LogEntry> {
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

    Some(LogEntry::from_local_time(
        Local.ymd(year, month, day).and_hms(h, m, s),
        caps.get(7).map(|x| x.as_bytes()).unwrap(),
    ))
}

pub fn parse_ue4_log_entry(bytes: &[u8]) -> Option<LogEntry> {
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

    Some(LogEntry::from_local_time(
        Local.ymd(year, month, day).and_hms(h, m, s),
        caps.get(7).map(|x| x.as_bytes()).unwrap(),
    ))
}

pub fn parse_log_entry(bytes: &[u8]) -> Option<LogEntry> {
    macro_rules! attempt {
        ($func:ident) => {
            if let Some(rv) = $func(bytes) {
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

#[test]
fn test_parse_c_log_entry() {
    let le = parse_c_log_entry(b"Tue Nov 21 00:30:05 2017 More stuff here").unwrap();
    let dt = le.local_timestamp().unwrap();
    assert_eq!(dt.month(), 11);
    assert_eq!(dt.day(), 21);
    assert_eq!(dt.hour(), 0);
    assert_eq!(dt.minute(), 30);
    assert_eq!(dt.second(), 5);
    assert_eq!(le.message(), "More stuff here");
}

#[test]
fn test_parse_short_log_entry() {
    let le = parse_short_log_entry(b"Nov 20 21:56:01 herzog com.apple.xpc.launchd[1] (com.apple.preference.displays.MirrorDisplays): Service only ran for 0 seconds. Pushing respawn out by 10 seconds.").unwrap();
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
    let le = parse_short_log_entry(
        b"Mon Nov 20 00:31:19.005 <kernel> en0: Received EAPOL packet (length = 161)",
    )
    .unwrap();
    let dt = le.local_timestamp().unwrap();
    assert_eq!(dt.month(), 11);
    assert_eq!(dt.day(), 20);
    assert_eq!(dt.hour(), 0);
    assert_eq!(dt.minute(), 31);
    assert_eq!(dt.second(), 19);
    assert_eq!(
        le.message(),
        "<kernel> en0: Received EAPOL packet (length = 161)"
    );
}

#[test]
fn test_parse_simple_log_entry() {
    let le = parse_simple_log_entry(
        b"22:07:10 server  | detected binary path: /Users/mitsuhiko/.virtualenvs/sentry/bin/uwsgi",
    )
    .unwrap();
    let dt = le.local_timestamp().unwrap();
    assert_eq!(dt.hour(), 22);
    assert_eq!(dt.minute(), 7);
    assert_eq!(dt.second(), 10);
    assert_eq!(
        le.message(),
        "server  | detected binary path: /Users/mitsuhiko/.virtualenvs/sentry/bin/uwsgi"
    );
}

#[test]
fn test_parse_common_log_entry() {
    let le = parse_common_log_entry(b"2015-05-13 17:39:16 +0200: Repaired 'Library/Printers/Canon/IJScanner/Resources/Parameters/CNQ9601'").unwrap();
    let dt = le.utc_timestamp().unwrap();
    assert_eq!(dt.year(), 2015);
    assert_eq!(dt.month(), 5);
    assert_eq!(dt.day(), 13);
    assert_eq!(dt.hour(), 15);
    assert_eq!(dt.minute(), 39);
    assert_eq!(dt.second(), 16);
    assert_eq!(
        le.message(),
        "Repaired 'Library/Printers/Canon/IJScanner/Resources/Parameters/CNQ9601'"
    );
}

#[test]
fn test_parse_common_alt_log_entry() {
    let le = parse_common_alt_log_entry(
        b"Mon Oct  5 11:40:10 2015	[INFO] PDApp.ExternalGateway - NativePlatformHandler destructed",
    )
    .unwrap();
    let dt = le.local_timestamp().unwrap();
    assert_eq!(dt.year(), 2015);
    assert_eq!(dt.month(), 10);
    assert_eq!(dt.day(), 5);
    assert_eq!(dt.hour(), 11);
    assert_eq!(dt.minute(), 40);
    assert_eq!(dt.second(), 10);
    assert_eq!(
        le.message(),
        "[INFO] PDApp.ExternalGateway - NativePlatformHandler destructed"
    );
}

#[test]
fn test_parse_common_alt2_log_entry() {
    let le = parse_common_alt2_log_entry(
        b"Jan 03, 2016 22:29:55 [0x70000073b000] DEBUG - Responding HTTP/1.1 200",
    )
    .unwrap();
    let dt = le.local_timestamp().unwrap();
    assert_eq!(dt.year(), 2016);
    assert_eq!(dt.month(), 1);
    assert_eq!(dt.day(), 3);
    assert_eq!(dt.hour(), 22);
    assert_eq!(dt.minute(), 29);
    assert_eq!(dt.second(), 55);
    assert_eq!(
        le.message(),
        "[0x70000073b000] DEBUG - Responding HTTP/1.1 200"
    );
}

#[test]
fn test_parse_webserver_log() {
    let le = parse_common_alt_log_entry(b"[Sun Feb 25 06:11:12.043123448 2018] [:notice] [pid 1:tid 2] process manager initialized (pid 1)").unwrap();
    let dt = le.local_timestamp().unwrap();
    assert_eq!(dt.year(), 2018);
    assert_eq!(dt.month(), 2);
    assert_eq!(dt.day(), 25);
    assert_eq!(dt.hour(), 6);
    assert_eq!(dt.minute(), 11);
    assert_eq!(dt.second(), 12);
    assert_eq!(
        le.message(),
        "[:notice] [pid 1:tid 2] process manager initialized (pid 1)"
    );
}
