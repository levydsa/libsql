use std::{cell::RefCell, num::NonZeroU32, ptr};

use aes::{
    cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut},
    Aes256,
};
use libsql_sys::{
    ffi::libsql_pghdr,
    wal::{wrapper::WrapWal, PageHeaderPool, PageHeaders, Wal, WalManager},
};
use pretty_hex::*;

#[derive(Clone)]
struct CryptWal {
    decryptor: cbc::Decryptor<Aes256>,
    encryptor: cbc::Encryptor<Aes256>,
}

impl<W: Wal> WrapWal<W> for CryptWal {
    fn read_frame(
        &mut self,
        wrapped: &mut W,
        frame_no: std::num::NonZeroU32,
        buffer: &mut [u8],
    ) -> libsql_sys::wal::Result<()> {
        assert_eq!(buffer.len(), 4096);

        if frame_no == NonZeroU32::new(1).unwrap() {
            wrapped.read_frame(frame_no, buffer)?;
        } else {
            wrapped.read_frame(frame_no, buffer)?;
            self.decryptor
                .clone()
                .decrypt_padded_mut::<NoPadding>(buffer)
                .expect("4096 is divisable by block size");
        }

        println!("read ({}) {:?}", frame_no, buffer.hex_dump());

        Ok(())
    }

    fn insert_frames(
        &mut self,
        wrapped: &mut W,
        page_size: std::ffi::c_int,
        page_headers: &mut libsql_sys::wal::PageHeaders,
        size_after: u32,
        is_commit: bool,
        sync_flags: std::ffi::c_int,
    ) -> libsql_sys::wal::Result<usize> {
        let mut ph = PageHeaderPool::from(page_headers.as_ptr());

        ph.pages
            .iter_mut()
            .zip(ph.headers.iter())
            .for_each(|(page, libsql_pghdr { pgno, .. })| {
                if *pgno != 1 {
                    self.encryptor
                        .clone()
                        .encrypt_padded_mut::<NoPadding>(page, page_size as usize)
                        .expect("pages are 4096 bytes");
                }
                println!("pool insert {pgno:?} {:?}", page.hex_dump());
            });

        let mut page_headers = unsafe {
            PageHeaders::from_raw(
                ph.headers
                    .first_mut()
                    .map(|a| a as *mut _)
                    .unwrap_or(ptr::null_mut()),
            )
        };

        wrapped.insert_frames(
            page_size,
            &mut page_headers,
            size_after,
            is_commit,
            sync_flags,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::{
        ffi::OsStr,
        path::{Path, PathBuf},
        str::FromStr,
        sync::Arc,
    };

    use aes::cipher::KeyIvInit;
    use cbc::Decryptor;
    use hmac::{Hmac, Mac};
    use libsql_sys::wal::{wrapper::WalWrapper, WalManager};
    use libsql_sys::{connection::OpenFlags, name::NamespaceName};
    use libsql_wal::{registry::WalRegistry, wal::LibsqlWalManager};
    use sha2::Sha256;

    use super::*;

    #[test]
    fn insert_and_read_page() {
        let resolver = |path: &Path| {
            if path.file_name().unwrap() != "data" {
                return NamespaceName::from_string(
                    path.file_name().unwrap().to_str().unwrap().to_string(),
                );
            }
            let name = path
                .parent()
                .and_then(Path::file_name)
                .and_then(OsStr::to_str)
                .map(ToString::to_string)
                .unwrap();

            NamespaceName::from_string(name)
        };

        let key = "secret";
        let mut mac = Hmac::<Sha256>::new_from_slice(b"secret").unwrap();
        mac.update(key.as_bytes());
        let key_h = mac.finalize().into_bytes();
        let iv = [42u8; 16];
        let encryptor = cbc::Encryptor::<Aes256>::new(&key_h.into(), &iv.into());
        let decryptor = cbc::Decryptor::<Aes256>::new(&key_h.into(), &iv.into());

        let registry = Arc::new({
            let (sender, _receiver) = tokio::sync::mpsc::channel(64);
            WalRegistry::new(
                "test/wals".into(),
                libsql_wal::storage::TestStorage::new().into(),
                sender,
            )
            .unwrap()
        });
        let wal = WalWrapper::new(
            CryptWal {
                decryptor,
                encryptor,
            },
            LibsqlWalManager::new(registry.clone(), Arc::new(resolver)),
        );
        let conn = libsql_sys::Connection::open(
            PathBuf::from_str("test/test.db").unwrap(),
            OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_READ_WRITE,
            wal.clone(),
            100000,
            None,
        )
        .unwrap();

        conn.execute("create table if not exists test(a integer)", [])
            .unwrap();
        conn.execute("insert into test (a) values (1)", []).unwrap();
        conn.execute("insert into test (a) values (2)", []).unwrap();
        conn.execute("insert into test (a) values (3)", []).unwrap();
        conn.query_row("select (a) from test", [], |_| Ok(()))
            .unwrap();
    }
}
