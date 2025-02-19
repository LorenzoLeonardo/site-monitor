mod auth;
mod config;
mod emailer;
mod error;
mod interface;
mod monitor;
mod profile;
mod watcher;

use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::io::Write;
use std::path::PathBuf;
use std::str::FromStr;

use async_curl::CurlActor;
use chrono::Local;
use config::Config;

use log::LevelFilter;
use tokio::select;
use tokio::sync::mpsc::channel;

use interface::production::Production;
use watcher::WatcherAction;

#[derive(Debug, strum_macros::Display)]
enum Stats {
    Up,
    Down,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    let log_level = if args.len() <= 1 {
        "info"
    } else {
        args[1].as_str()
    };
    let log_level = LevelFilter::from_str(log_level)
        .expect("Log level input must be: off, error, warn, info, debug, trace");
    init_logger(log_level);
    let name = env!("CARGO_PKG_NAME");
    let version = env!("CARGO_PKG_VERSION");
    log::info!("{name} has started v{version}...");
    log::info!("Log {:?}", log_level);

    let config = Config::load().unwrap();
    let interface = Production::new(CurlActor::new(), config);

    let _ = auth::request_token(interface.clone()).await?;
    let (tx, mut rx) = channel(1);
    let _ = watcher::watch_file(tx, PathBuf::from_str("websites.txt")?).await;

    let mut hash_map_task = HashMap::new();

    loop {
        select! {
            Some(msg) = rx.recv() => {
                match msg {
                    WatcherAction::Add(sites) => {
                        for site in sites {
                            let site_inner = site.clone();
                            let inner_interface = interface.clone();
                            let handle = tokio::spawn(async move {
                                if let Err(err) = monitor::monitor_site(inner_interface, site_inner.as_str()).await {
                                    log::error!("[{}] {}", site_inner.as_str(), err.to_string());
                                }
                            });
                            log::info!("[{site}] was just added into monitoring.");
                            hash_map_task.insert(site, handle);
                         }
                    },
                    WatcherAction::Remove(sites) => {
                        for site in sites {
                            if let Some(value) = hash_map_task.remove(&site) {
                                value.abort();
                                log::info!("[{site}] was just removed from monitoring.");
                            }
                        }
                    }
                }
            }
        }
    }
}

pub fn init_logger(level: LevelFilter) {
    let mut log_builder = env_logger::Builder::new();
    log_builder.format(|buf, record| {
        let mut module = "";
        if let Some(path) = record.module_path() {
            if let Some(split) = path.split("::").last() {
                module = split;
            }
        }

        writeln!(
            buf,
            "[{}][{}]> {}: {}",
            Local::now().format("%b-%d-%Y %H:%M:%S.%f"),
            record.level(),
            module,
            record.args()
        )
    });

    log_builder.filter_level(level);
    if let Err(e) = log_builder.try_init() {
        log::error!("{:?}", e);
    }
}
