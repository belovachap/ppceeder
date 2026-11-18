// src/log.rs

use std::fmt;
use std::fs::File;
use std::io::Write;
use std::sync::{Mutex, OnceLock};
use std::time::SystemTime;

static LOGGER: OnceLock<Mutex<Logger>> = OnceLock::new();

pub fn get_logger() -> &'static Mutex<Logger> {
    LOGGER.get_or_init(|| Mutex::new(Logger::new()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Fatal,
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            LogLevel::Trace => "TRACE",
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
            LogLevel::Fatal => "FATAL",
        };
        write!(f, "{:<5}", name)
    }
}

pub struct Logger {
    level: LogLevel,
    quiet: bool,
    fp: Option<File>,
}

impl Logger {
    pub fn new() -> Self {
        Logger {
            level: LogLevel::Trace,
            quiet: false,
            fp: None,
        }
    }

    pub fn set_level(&mut self, level: LogLevel) {
        self.level = level;
    }

    #[allow(dead_code)]
    pub fn set_quiet(&mut self, enable: bool) {
        self.quiet = enable;
    }

    #[allow(dead_code)]
    pub fn set_fp(&mut self, fp: Option<File>) {
        self.fp = fp;
    }

    pub fn log(&mut self, level: LogLevel, file: &str, line: u32, msg: &str) {
        if level < self.level {
            return;
        }

        let timestamp = format_timestamp();

        // Log to stderr
        if !self.quiet {
            eprintln!("{} {} {}:{}: {}", timestamp, level, file, line, msg);
        }

        // Log to file
        if let Some(ref mut fp) = self.fp {
            let _ = writeln!(fp, "{} {} {}:{}: {}", timestamp, level, file, line, msg);
            let _ = fp.flush();
        }
    }
}

impl Default for Logger {
    fn default() -> Self {
        Self::new()
    }
}

fn format_timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let hours = (secs / 3600) % 24;
    let minutes = (secs / 60) % 60;
    let seconds = secs % 60;
    format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
}

/// Convenience macros that mirror the C macros.
#[macro_export]
macro_rules! log_trace {
    ($_logger:expr, $($arg:tt)*) => {
        $crate::log::get_logger().lock().unwrap().log($crate::log::LogLevel::Trace, file!(), line!(), &format!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_debug {
    ($_logger:expr, $($arg:tt)*) => {
        $crate::log::get_logger().lock().unwrap().log($crate::log::LogLevel::Debug, file!(), line!(), &format!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_info {
    ($_logger:expr, $($arg:tt)*) => {
        $crate::log::get_logger().lock().unwrap().log($crate::log::LogLevel::Info, file!(), line!(), &format!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_warn {
    ($_logger:expr, $($arg:tt)*) => {
        $crate::log::get_logger().lock().unwrap().log($crate::log::LogLevel::Warn, file!(), line!(), &format!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_error {
    ($_logger:expr, $($arg:tt)*) => {
        $crate::log::get_logger().lock().unwrap().log($crate::log::LogLevel::Error, file!(), line!(), &format!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_fatal {
    ($_logger:expr, $($arg:tt)*) => {
        $crate::log::get_logger().lock().unwrap().log($crate::log::LogLevel::Fatal, file!(), line!(), &format!($($arg)*))
    };
}

