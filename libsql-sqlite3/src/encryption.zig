const std = @import("std");
const c = @cImport(@cInclude("sqlite3.h"));
const assert = std.debug.assert;

const Type = enum {
    Integer,
    Blob,
    Text,
    Float,
};

const Statement = struct {
    inner: *c.sqlite3_stmt,

    pub fn column_count(self: Statement) i32 {
        return c.sqlite3_column_count(self.inner);
    }

    pub fn column_text(self: Statement, i: i32) [:0]const u8 {
        return std.mem.sliceTo(c.sqlite3_column_text(self.inner, i), 0);
    }

    pub fn column_type(self: Statement, i: i32) !Type {
        return switch (c.sqlite3_column_type(self.inner, i)) {
            c.SQLITE_INTEGER => .integer,
            c.SQLITE_BLOB => .blob,
            c.SQLITE_TEXT => .text,
            c.SQLITE_FLOAT => .float,
            else => |rc| {
                std.log.err("{s}\n", .{err(rc)});
                return error.SqliteError;
            },
        };
    }

    pub fn count(self: Statement) usize {
        return @intCast(c.sqlite3_data_count(self.inner));
    }

    pub fn step(stmt: Statement) !bool {
        return switch (c.sqlite3_step(stmt.inner)) {
            c.SQLITE_ROW => true,
            c.SQLITE_DONE => false,
            else => |rc| {
                std.debug.print("{s}", .{err(rc)});
                return error.SqliteError;
            },
        };
    }

    pub fn deinit(stmt: Statement) void {
        _ = c.sqlite3_finalize(stmt.inner);
    }
};

pub fn err(rc: i32) []const u8 {
    return std.mem.sliceTo(c.sqlite3_errstr(rc), 0);
}

const Database = struct {
    inner: *c.sqlite3,

    pub fn init(filename: [:0]const u8) !Database {
        var db: *c.sqlite3 = undefined;
        if (c.sqlite3_open(filename, @ptrCast(&db)) != c.SQLITE_OK) {
            std.log.err("{s}", .{c.sqlite3_errmsg(db)});
            return error.SqliteFailedInit;
        }

        return .{
            .inner = db,
        };
    }

    pub fn deinit(self: Database) void {
        _ = c.sqlite3_close(self.inner);
    }

    pub fn prepare(self: Database, sql: []const u8) !Statement {
        var stmt: *c.sqlite3_stmt = undefined;

        switch (c.sqlite3_prepare_v2(
            self.inner,
            sql.ptr,
            @intCast(sql.len), // @intCast(sql.len),
            @ptrCast(&stmt),
            null,
        )) {
            c.SQLITE_OK => return .{ .inner = stmt },
            else => |rc| {
                std.debug.print("{s}", .{err(rc)});
                return error.SqliteError;
            },
        }
    }
};

pub const libsql_crypt_file = extern struct {
    base: c.sqlite3_file,
    file: *c.sqlite3_file,
    name: ?[*:0]const u8,
    vsf: ?*libsql_crypt_vfs,
    page_no: i32 = 0,
    flags: i32,
};

const OpenFlag = packed struct {
    read_only: bool = false,
    read_write: bool = false,
    create: bool = false,
    delete_on_close: bool = false,
    exclusive: bool = false,
    auto_proxy: bool = false,
    uri: bool = false,
    memory: bool = false,

    main_db: bool = false,
    temp_db: bool = false,
    transient_db: bool = false,
    main_journal: bool = false,
    temp_journal: bool = false,
    sub_journal: bool = false,
    super_journal: bool = false,

    no_mutex: bool = false,
    full_mutex: bool = false,
    shared_cache: bool = false,
    private_cache: bool = false,

    wal: bool = false,

    _1: u4 = 0,

    no_follow: bool = false,
    extension_rc: bool = false,

    _2: u6 = 0,

    pub fn fromInt(flags: i32) OpenFlag {
        return @bitCast(flags);
    }

    comptime {
        for (&.{
            .{ c.SQLITE_OPEN_READONLY, "read_only" },
            .{ c.SQLITE_OPEN_READWRITE, "read_write" },
            .{ c.SQLITE_OPEN_CREATE, "create" },
            .{ c.SQLITE_OPEN_DELETEONCLOSE, "delete_on_close" },
            .{ c.SQLITE_OPEN_EXCLUSIVE, "exclusive" },
            .{ c.SQLITE_OPEN_AUTOPROXY, "auto_proxy" },
            .{ c.SQLITE_OPEN_URI, "uri" },
            .{ c.SQLITE_OPEN_MEMORY, "memory" },
            .{ c.SQLITE_OPEN_MAIN_DB, "main_db" },
            .{ c.SQLITE_OPEN_TEMP_DB, "temp_db" },
            .{ c.SQLITE_OPEN_TRANSIENT_DB, "transient_db" },
            .{ c.SQLITE_OPEN_MAIN_JOURNAL, "main_journal" },
            .{ c.SQLITE_OPEN_TEMP_JOURNAL, "temp_journal" },
            .{ c.SQLITE_OPEN_SUBJOURNAL, "sub_journal" },
            .{ c.SQLITE_OPEN_SUPER_JOURNAL, "super_journal" },
            .{ c.SQLITE_OPEN_NOMUTEX, "no_mutex" },
            .{ c.SQLITE_OPEN_FULLMUTEX, "full_mutex" },
            .{ c.SQLITE_OPEN_SHAREDCACHE, "shared_cache" },
            .{ c.SQLITE_OPEN_PRIVATECACHE, "private_cache" },
            .{ c.SQLITE_OPEN_WAL, "wal" },
            .{ c.SQLITE_OPEN_NOFOLLOW, "no_follow" },
            .{ c.SQLITE_OPEN_EXRESCODE, "extension_rc" },
        }) |pair| {
            const flag, const field_name = pair;
            std.testing.expectEqual(
                flag,
                1 << @bitOffsetOf(OpenFlag, field_name),
            ) catch unreachable;
        }
    }
};

const VfsFlag = enum {
    Main,
    Wal,
    Temp,
    Transient,
    MainJournal,
    TempJournal,
    SubJournal,
    SuperJournal,

    pub fn fromOpenFlag(open_flag: OpenFlag) ?VfsFlag {
        return if (open_flag.main_db)
            .Main
        else if (open_flag.temp_db)
            .Temp
        else if (open_flag.transient_db)
            .Transient
        else if (open_flag.main_journal)
            .MainJournal
        else if (open_flag.temp_journal)
            .TempJournal
        else if (open_flag.sub_journal)
            .SubJournal
        else if (open_flag.super_journal)
            .SuperJournal
        else if (open_flag.wal)
            .Wal
        else
            null;
    }
};

pub const libsql_crypt_vfs = extern struct {
    /// base sqlite3_vsf used to interact with the base filesystem
    base: *c.sqlite3_vfs,
    mutex: *std.Thread.Mutex,
    main_list: *std.ArrayList(*libsql_crypt_file),

    const vfs_name: [:0]const u8 = "libsql_cypher";

    pub fn open(
        vsf: ?*c.sqlite3_vfs,
        filename: ?[*:0]const u8,
        in_file: ?*c.sqlite3_file,
        flags: i32,
        out_flags: ?*i32,
    ) callconv(.C) i32 {
        const self: *libsql_crypt_vfs = @ptrCast(vsf.?);

        const file: *libsql_crypt_file = @ptrCast(in_file);
        file.name = filename;

        const vfs_flag = VfsFlag.fromOpenFlag(OpenFlag.fromInt(flags)) orelse {
            return c.SQLITE_MISUSE;
        };

        std.log.info("crypt open {s}: {*} {?s}", .{
            @tagName(vfs_flag),
            file,
            filename,
        });

        switch ((self.base.xOpen orelse {
            return c.SQLITE_INTERNAL;
        })(self.base, filename, file.file, flags, out_flags)) {
            c.SQLITE_OK => {
                if (vfs_flag == .Main) {
                    self.mutex.lock();
                    defer self.mutex.unlock();

                    self.main_list.append(file) catch {
                        return c.SQLITE_NOMEM;
                    };
                }

                return c.SQLITE_OK;
            },
            else => |rc| return rc,
        }
    }
};

test "sqlite init" {
    const db = try Database.init(":memory:");
    defer db.deinit();

    const stmt = try db.prepare("pragma compile_options");
    defer stmt.deinit();

    const this: c.sqlite3_vfs = .{
        .zName = libsql_crypt_vfs.vfs_name,
        .xOpen = libsql_crypt_vfs.open,
    };
    _ = this;

    while (try stmt.step()) {
        std.debug.print("{s}\n", .{stmt.column_text(0)});
    }
}
