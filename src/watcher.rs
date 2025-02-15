use std::path::PathBuf;

use tokio::{
    fs::File,
    io::{self, AsyncBufReadExt},
    sync::mpsc::Sender,
};

use crate::error::SiteMonitorResult;

pub enum WatcherAction {
    Add(Vec<String>),
    Remove(Vec<String>),
}

pub async fn watch_file(tx: Sender<WatcherAction>, path: PathBuf) -> SiteMonitorResult<()> {
    tokio::spawn(async move {
        let mut previous = Vec::new();
        let mut current = Vec::new();

        loop {
            let file = File::open(&path).await.unwrap();
            let reader = io::BufReader::new(file);
            let mut lines = reader.lines();
            while let Some(line) = lines.next_line().await.unwrap_or_else(|_| None) {
                current.push(line);
            }

            let deleted_entries: Vec<_> = previous
                .iter()
                .filter(|&item| !current.contains(item))
                .cloned()
                .collect();
            let new_entries: Vec<String> = current
                .iter()
                .filter(|&item| !previous.contains(item))
                .cloned()
                .collect();

            log::debug!("Current sites: {:?}", current);
            log::debug!("New sites: {:?}", new_entries);
            log::debug!("Deleted sites: {:?}", deleted_entries);
            if !new_entries.is_empty() {
                let _ = tx
                    .send(WatcherAction::Add(new_entries))
                    .await
                    .map_err(|err| {
                        log::error!("{err}");
                    });
            }

            if !deleted_entries.is_empty() {
                let _ = tx
                    .send(WatcherAction::Remove(deleted_entries))
                    .await
                    .map_err(|err| {
                        log::error!("{err}");
                    });
            }
            previous = current.clone();
            current.clear();
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    });
    Ok(())
}
