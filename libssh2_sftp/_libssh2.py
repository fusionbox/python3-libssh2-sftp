from cffi import FFI

ffi = FFI()
ffi.cdef("""
    typedef ... LIBSSH2_SESSION;
    typedef ... LIBSSH2_SFTP;
    typedef ... LIBSSH2_SFTP_HANDLE;
    typedef int libssh2_socket_t;

    struct LIBSSH2_SFTP_ATTRIBUTES {
        /* If flags & ATTR_* bit is set, then the value in this struct will be
         * meaningful Otherwise it should be ignored
         */
        unsigned long flags;

        uint64_t      filesize;
        unsigned long uid, gid;
        unsigned long permissions;
        unsigned long atime, mtime;
    };
    typedef struct LIBSSH2_SFTP_ATTRIBUTES LIBSSH2_SFTP_ATTRIBUTES;

    typedef void (*LIBSSH2_ALLOC_FUNC)(size_t count, void **abstract);
    typedef void (*LIBSSH2_REALLOC_FUNC)(void *ptr, size_t count, void **abstract);
    typedef void (LIBSSH2_FREE_FUNC)(void *ptr, void *abstract);

    typedef void (LIBSSH2_PASSWD_CHANGEREQ_FUNC)(LIBSSH2_SESSION *session, char **newpw,
                                                 int *newpw_len, void **abstract);

    #define LIBSSH2_HOSTKEY_HASH_MD5  1
    #define LIBSSH2_HOSTKEY_HASH_SHA1 2

    #define SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT    1
    #define SSH_DISCONNECT_PROTOCOL_ERROR                 2
    #define SSH_DISCONNECT_KEY_EXCHANGE_FAILED            3
    #define SSH_DISCONNECT_RESERVED                       4
    #define SSH_DISCONNECT_MAC_ERROR                      5
    #define SSH_DISCONNECT_COMPRESSION_ERROR              6
    #define SSH_DISCONNECT_SERVICE_NOT_AVAILABLE          7
    #define SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED 8
    #define SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE        9
    #define SSH_DISCONNECT_CONNECTION_LOST                10
    #define SSH_DISCONNECT_BY_APPLICATION                 11
    #define SSH_DISCONNECT_TOO_MANY_CONNECTIONS           12
    #define SSH_DISCONNECT_AUTH_CANCELLED_BY_USER         13
    #define SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE 14
    #define SSH_DISCONNECT_ILLEGAL_USER_NAME              15

    #define LIBSSH2_FXF_READ   0x00000001
    #define LIBSSH2_FXF_WRITE  0x00000002
    #define LIBSSH2_FXF_APPEND 0x00000004
    #define LIBSSH2_FXF_CREAT  0x00000008
    #define LIBSSH2_FXF_TRUNC  0x00000010
    #define LIBSSH2_FXF_EXCL   0x00000020


    #define LIBSSH2_SFTP_OPENFILE 0
    #define LIBSSH2_SFTP_OPENDIR  1

    int libssh2_init(int flags);

    int libssh2_exit(void);

    LIBSSH2_SESSION *libssh2_session_init_ex(LIBSSH2_ALLOC_FUNC *myalloc,
                                             LIBSSH2_FREE_FUNC *myfree,
                                             LIBSSH2_REALLOC_FUNC *myrealloc,
                                             void *abstract);

    int libssh2_session_free(LIBSSH2_SESSION *session);

    int libssh2_session_handshake(LIBSSH2_SESSION *session, libssh2_socket_t socket);

    int libssh2_session_disconnect_ex(LIBSSH2_SESSION *session, int reason,
                                      const char *description, const char *lang);

    const char *libssh2_hostkey_hash(LIBSSH2_SESSION *session, int hash_type);

    int libssh2_userauth_password_ex(LIBSSH2_SESSION *session, const char *username,
                                     unsigned int username_len, const char *password,
                                     unsigned int password_len,
                                     LIBSSH2_PASSWD_CHANGEREQ_FUNC *passwd_change_cb);

    char *libssh2_userauth_list(LIBSSH2_SESSION *session, const char *username,
                                unsigned int username_len);

    LIBSSH2_SFTP *libssh2_sftp_init(LIBSSH2_SESSION *session);

    LIBSSH2_SFTP_HANDLE *libssh2_sftp_open_ex(LIBSSH2_SFTP *sftp, const char *filename,
                                              unsigned int filename_len, unsigned long flags,
                                              long mode, int open_type);

    int libssh2_sftp_shutdown(LIBSSH2_SFTP *sftp);

    int libssh2_sftp_read(LIBSSH2_SFTP_HANDLE *handle, char *buffer, size_t buffer_maxlen);

    int libssh2_sftp_close_handle(LIBSSH2_SFTP_HANDLE *handle);

    int libssh2_sftp_readdir_ex(LIBSSH2_SFTP_HANDLE *handle, char *buffer, size_t buffer_maxlen,
                                char *longentry, size_t longentry_maxlen,
                                LIBSSH2_SFTP_ATTRIBUTES *attrs);

""")


lib = ffi.dlopen('libssh2.so')


def libssh2_session_init():
    return ffi.gc(
        lib.libssh2_session_init_ex(ffi.NULL, ffi.NULL, ffi.NULL, ffi.NULL),
        lib.libssh2_session_free
    )


def libssh2_userauth_password(session, username, password):
    return lib.libssh2_userauth_password_ex(
        session, username, len(username), password, len(password), ffi.NULL)

def libssh2_sftp_open(sftp, filename, flags, mode):
    return lib.libssh2_sftp_open_ex(
        sftp, filename, len(filename), flags, mode, lib.LIBSSH2_SFTP_OPENFILE)


def libssh2_session_disconnect(session, description):
    return lib.libssh2_session_disconnect_ex(
        session, lib.SSH_DISCONNECT_BY_APPLICATION, description, b""
    )


def libssh2_sftp_opendir(sftp, path):
    return lib.libssh2_sftp_open_ex(sftp, path, len(path), 0, 0, lib.LIBSSH2_SFTP_OPENDIR)


def libssh2_sftp_closedir(handle):
    return lib.libssh2_sftp_close_handle(handle)


def libssh2_sftp_close(handle):
    return lib.libssh2_sftp_close_handle(handle)
