use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;
use crossbeam::deque::Injector;
use crossbeam::sync::Unparker;
use parking_lot::{Mutex, MutexGuard};

use crate::error::{Error, Result};
use crate::io::file::FileExt;
use crate::io::Io;
use crate::registry::WalRegistry;
use crate::segment::current::CurrentSegment;
use crate::transaction::{ReadTransaction, Savepoint, Transaction, TxGuard, WriteTransaction};
use libsql_sys::name::NamespaceName;

#[derive(Default)]
pub struct WalLock {
    pub(crate) tx_id: Arc<Mutex<Option<u64>>>,
    /// When a writer is popped from the write queue, its write transaction may not be reading from the most recent
    /// snapshot. In this case, we return `SQLITE_BUSY_SNAPHSOT` to the caller. If no reads were performed
    /// with that transaction before upgrading, then the caller will call us back immediately after re-acquiring
    /// a read mark.
    /// Without the reserved slot, the writer would be re-enqueued, a writer before it would be inserted,
    /// and we'd find ourselves in the initial situation. Instead, we use the reserved slot to bypass the queue when the
    /// writer tried to re-acquire the write lock.
    pub(crate) reserved: Mutex<Option<u64>>,
    next_tx_id: AtomicU64,
    pub(crate) waiters: Injector<(Unparker, u64)>,
}

pub struct SharedWal<IO: Io> {
    pub(crate) current: ArcSwap<CurrentSegment<IO::File>>,
    pub(crate) wal_lock: Arc<WalLock>,
    pub(crate) db_file: IO::File,
    pub(crate) namespace: NamespaceName,
    pub(crate) registry: Arc<WalRegistry<IO>>,
    #[allow(dead_code)] // used by replication
    pub(crate) checkpointed_frame_no: AtomicU64,
    pub(crate) new_frame_notifier: tokio::sync::watch::Sender<u64>,
}

impl<IO: Io> SharedWal<IO> {
    pub fn db_size(&self) -> u32 {
        self.current.load().db_size()
    }

    #[tracing::instrument(skip_all)]
    pub fn begin_read(&self, conn_id: u64) -> ReadTransaction<IO::File> {
        // FIXME: this is not enough to just increment the counter, we must make sure that the segment
        // is not sealed. If the segment is sealed, retry with the current segment
        let current = self.current.load();
        current.inc_reader_count();
        let (max_frame_no, db_size) =
            current.with_header(|header| (header.last_committed(), header.db_size()));
        let id = self.wal_lock.next_tx_id.fetch_add(1, Ordering::Relaxed);
        ReadTransaction {
            id,
            max_frame_no,
            current: current.clone(),
            db_size,
            created_at: Instant::now(),
            conn_id,
            pages_read: 0,
        }
    }

    /// Upgrade a read transaction to a write transaction
    pub fn upgrade(&self, tx: &mut Transaction<IO::File>) -> Result<()> {
        loop {
            match tx {
                Transaction::Write(_) => unreachable!("already in a write transaction"),
                Transaction::Read(read_tx) => {
                    {
                        let mut reserved = self.wal_lock.reserved.lock();
                        match *reserved {
                            // we have already reserved the slot, go ahead and try to acquire
                            Some(id) if id == read_tx.conn_id => {
                                tracing::trace!("taking reserved slot");
                                reserved.take();
                                let lock = self.wal_lock.tx_id.lock();
                                let write_tx = self.acquire_write(read_tx, lock, reserved)?;
                                *tx = Transaction::Write(write_tx);
                                return Ok(());
                            }
                            _ => (),
                        }
                    }

                    let lock = self.wal_lock.tx_id.lock();
                    match *lock {
                        None if self.wal_lock.waiters.is_empty() => {
                            let write_tx =
                                self.acquire_write(read_tx, lock, self.wal_lock.reserved.lock())?;
                            *tx = Transaction::Write(write_tx);
                            return Ok(());
                        }
                        Some(_) | None => {
                            tracing::trace!(
                                "txn currently held by another connection, registering to wait queue"
                            );
                            let parker = crossbeam::sync::Parker::new();
                            let unparker = parker.unparker().clone();
                            self.wal_lock.waiters.push((unparker, read_tx.conn_id));
                            drop(lock);
                            parker.park();
                        }
                    }
                }
            }
        }
    }

    fn acquire_write(
        &self,
        read_tx: &ReadTransaction<IO::File>,
        mut tx_id_lock: MutexGuard<Option<u64>>,
        mut reserved: MutexGuard<Option<u64>>,
    ) -> Result<WriteTransaction<IO::File>> {
        // we read two fields in the header. There is no risk that a transaction commit in
        // between the two reads because this would require that:
        // 1) there would be a running txn
        // 2) that transaction held the lock to tx_id (be in a transaction critical section)
        let current = self.current.load();
        let last_commited = current.last_committed();
        if read_tx.max_frame_no != last_commited || current.is_sealed() {
            if read_tx.pages_read <= 1 {
                // this transaction hasn't read anything yet, it will retry to
                // acquire the lock, reserved the slot so that it can make
                // progress quickly
                // TODO: is it possible that we upgrade the read lock ourselves, so we don't need
                // that reserved stuff anymore? If nothing was read, just upgrade the read,
                // otherwise return snapshot busy and let the connection do the cleanup.
                tracing::debug!("reserving tx slot");
                reserved.replace(read_tx.conn_id);
            }
            return Err(Error::BusySnapshot);
        }
        let next_offset = current.count_committed() as u32;
        let next_frame_no = current.next_frame_no().get();
        *tx_id_lock = Some(read_tx.id);

        Ok(WriteTransaction {
            wal_lock: self.wal_lock.clone(),
            savepoints: vec![Savepoint {
                next_offset,
                next_frame_no,
                index: BTreeMap::new(),
            }],
            next_frame_no,
            next_offset,
            is_commited: false,
            read_tx: read_tx.clone(),
        })
    }

    #[tracing::instrument(skip(self, tx, buffer))]
    pub fn read_frame(
        &self,
        tx: &mut Transaction<IO::File>,
        page_no: u32,
        buffer: &mut [u8],
    ) -> Result<()> {
        match tx.current.find_frame(page_no, tx) {
            Some(offset) => {
                // some debug assertions to make sure invariants hold
                #[cfg(debug_assertions)]
                {
                    if let Ok(header) = tx.current.frame_header_at(offset) {
                        // the frame we got is not more recent than max frame_no
                        assert!(
                            header.frame_no() <= tx.max_frame_no(),
                            "read frame is greater than max frame, {}, {}",
                            header.frame_no(),
                            tx.max_frame_no()
                        );
                        // the page we got is the page we asked for
                        assert_eq!(header.page_no(), page_no);
                    }
                }

                tx.current.read_page_offset(offset, buffer)?;
            }
            None => {
                // locate in segments
                if !tx
                    .current
                    .tail()
                    .read_page(page_no, tx.max_frame_no, buffer)?
                {
                    // read from db_file
                    tracing::trace!(page_no, "reading from main file");
                    self.db_file
                        .read_exact_at(buffer, (page_no as u64 - 1) * 4096)?;
                }
            }
        }

        // The replication index from page 1 must match that of the SharedWal
        #[cfg(debug_assertions)]
        {
            use crossbeam::atomic::AtomicConsume;
            use libsql_sys::ffi::Sqlite3DbHeader;
            use zerocopy::FromBytes;

            if page_no == 1 {
                let header = Sqlite3DbHeader::read_from_prefix(buffer).unwrap();
                assert_eq!(
                    header.replication_index.get(),
                    self.checkpointed_frame_no.load_consume()
                );
            }
        }

        tx.pages_read += 1;

        Ok(())
    }

    #[tracing::instrument(skip_all, fields(tx_id = tx.id))]
    pub fn insert_frames<'a>(
        &self,
        tx: &mut WriteTransaction<IO::File>,
        pages: impl Iterator<Item = (u32, &'a [u8])>,
        size_after: Option<u32>,
    ) -> Result<()> {
        let current = self.current.load();
        let mut tx = tx.lock();
        if let Some(last_committed) = current.insert_pages(pages, size_after, &mut tx)? {
            self.new_frame_notifier.send_replace(last_committed);
        }

        // TODO: use config for max log size
        if tx.is_commited() && current.count_committed() > 1000 {
            self.swap_current(&tx)?;
        }

        Ok(())
    }

    /// Swap the current log. A write lock must be held, but the transaction must be must be committed already.
    fn swap_current(&self, tx: &TxGuard<IO::File>) -> Result<()> {
        self.registry.swap_current(self, tx)?;
        Ok(())
    }

    pub fn checkpoint(&self) -> Result<Option<u64>> {
        let current = self.current.load();
        match current.tail().checkpoint(&self.db_file)? {
            Some(frame_no) => {
                self.checkpointed_frame_no
                    .store(frame_no, Ordering::Relaxed);
                Ok(Some(frame_no))
            }
            None => Ok(None),
        }
    }

    pub fn last_committed_frame_no(&self) -> u64 {
        let current = self.current.load();
        current.last_committed_frame_no()
    }

    pub fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }
}

#[cfg(test)]
mod test {
    use std::path::Path;

    use crossbeam::atomic::AtomicConsume;
    use libsql_sys::rusqlite::OpenFlags;
    use tempfile::tempdir;

    use crate::wal::LibsqlWalManager;

    use super::*;

    #[test]
    fn checkpoint() {
        let tmp = tempdir().unwrap();
        let resolver = |path: &Path| {
            let name = path.file_name().unwrap().to_str().unwrap();
            NamespaceName::from_string(name.to_string())
        };

        let registry =
            Arc::new(WalRegistry::new(tmp.path().join("test/wals"), resolver, ()).unwrap());
        let wal_manager = LibsqlWalManager::new(registry.clone());

        let db_path = tmp.path().join("test/data");
        let conn = libsql_sys::Connection::open(
            db_path.clone(),
            OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_READ_WRITE,
            wal_manager.clone(),
            100000,
            None,
        )
        .unwrap();

        let shared = registry.open(&db_path).unwrap();

        assert_eq!(shared.checkpointed_frame_no.load_consume(), 0);

        conn.execute("create table test (x)", ()).unwrap();
        conn.execute("insert into test values (12)", ()).unwrap();
        conn.execute("insert into test values (12)", ()).unwrap();

        assert_eq!(shared.checkpointed_frame_no.load_consume(), 0);

        let mut tx = Transaction::Read(shared.begin_read(666));
        shared.upgrade(&mut tx).unwrap();
        {
            let mut tx = tx.as_write_mut().unwrap().lock();
            tx.commit();
            shared.swap_current(&tx).unwrap();
        }
        tx.end();

        let frame_no = shared.checkpoint().unwrap().unwrap();
        assert_eq!(frame_no, 4);
        assert_eq!(shared.checkpointed_frame_no.load_consume(), 4);

        assert!(shared.checkpoint().unwrap().is_none());
    }
}
