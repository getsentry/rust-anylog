//! `anylog` is a crate that tries to parse any potential log message it
//! would encounter and extract timestamp and message from it.  It supports a
//! wide range of formats and tries them all.
//!
//! This crate is used by [Sentry](https://sentry.io/) to parse logfiles into
//! breadcrumbs.
extern crate chrono;
extern crate regex;
#[macro_use]
extern crate lazy_static;

mod parser;
mod types;

pub use crate::types::LogEntry;
