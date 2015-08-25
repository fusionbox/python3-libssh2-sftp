import atexit
import socket
import io

from . import _libssh2

# A lock is aquired when importing, this can't happen in multiple threads
_libssh2.lib.libssh2_init(0)
atexit.register(_libssh2.lib.libssh2_exit)


class SSHError(Exception):
    pass


class HandshakeError(SSHError):
    pass


class SFTPError(SSHError):
    pass

class Session(object):
    def __init__(self, address):
        self._session = _libssh2.libssh2_session_init()

        self.sock = socket.create_connection(address)

        ret = _libssh2.lib.libssh2_session_handshake(self._session, self.sock.fileno())
        if ret != 0:  # TODO: Handle different return codes
            raise HandshakeError

    def get_sha1_fingerprint(self):
        # TODO: fingerprint can return NULL
        fingerprint = _libssh2.lib.libssh2_hostkey_hash(self._session, _libssh2.lib.LIBSSH2_HOSTKEY_HASH_SHA1)
        # No need to deallocate the fingerprint, it is stored on the session
        return bytes(_libssh2.ffi.buffer(fingerprint, 20))  # 20 is the size of a sha1 fingerprint

    def get_md5_fingerprint(self):
        # TODO: fingerprint can return NULL
        fingerprint = _libssh2.lib.libssh2_hostkey_hash(self._session, _libssh2.lib.LIBSSH2_HOSTKEY_HASH_MD5)
        # No need to deallocate the fingerprint, it is stored on the session
        return bytes(_libssh2.ffi.buffer(fingerprint, 16))  # 16 is the size of a sha1 fingerprint

    def authenticate(self, username, password):
        ret = _libssh2.libssh2_userauth_password(
            self._session, username.encode('utf-8'),
            password.encode('utf-8')
        )
        if ret != 0:  # TODO Handle different return codes
            raise SSHError

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        _libssh2.libssh2_session_disconnect(self._session, "See ya".encode('ascii'))
        self._session = None
        self.sock.close()

    def get_sftp(self):
        return SFTPSession(self)


class FileAttributes(object):
    def __init__(self, name, attrs):
        self.name = name.decode('utf-8', 'surrogateescape')

        self.mtime = attrs.mtime
        self.atime = attrs.atime
        self.flags = attrs.flags
        self.uid = attrs.uid
        self.gid = attrs.gid

    def __str__(self):
        return self.name

    def __repr__(self):
        return 'File({!r})'.format(self.name)


class SFTPSession(object):
    def __init__(self, ssh_session):
        self._ssh = ssh_session
        self._session = _libssh2.lib.libssh2_sftp_init(self._ssh._session)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        _libssh2.lib.libssh2_sftp_shutdown(self._session)
        self._session = None

    def listdir(self, path):
        handle = _libssh2.libssh2_sftp_opendir(self._session, path.encode('utf-8', 'surrogateescape'))
        if handle == _libssh2.ffi.NULL:
            raise SFTPError("Directory does not exist")
        acc = []  # If you don't accumulate a list, the context manager might get freed
        try:
            buf = _libssh2.ffi.new("char [512]")
            logentry = _libssh2.ffi.new("char [512]")
            attrs = _libssh2.ffi.new("LIBSSH2_SFTP_ATTRIBUTES *")

            while True:
                buflen = _libssh2.lib.libssh2_sftp_readdir_ex(
                    handle, buf, len(buf), logentry, len(logentry), attrs)
                if buflen == 0:
                    return acc
                elif buflen < 0:
                    raise SFTPError
                acc.append(FileAttributes(bytes(_libssh2.ffi.buffer(buf, buflen)), attrs))
        finally:
            _libssh2.libssh2_sftp_closedir(handle)

    def get_file_contents(self, fname, buffer_size=2**16):
        handle = _libssh2.libssh2_sftp_open(self._session, fname.encode('utf-8', 'surrogatescape'),
                                        _libssh2.lib.LIBSSH2_FXF_READ, 0)
        if handle == _libssh2.ffi.NULL:
            raise SFTPError("File does not exist")
        contents = io.BytesIO()
        try:
            buf = _libssh2.ffi.new("char []", buffer_size)
            while True:
                buflen = _libssh2.lib.libssh2_sftp_read(handle, buf, len(buf))
                if buflen == 0:
                    return contents.getvalue()
                elif buflen < 0:
                    raise SFTPError
                contents.write(bytes(_libssh2.ffi.buffer(buf, buflen)))
        finally:
            _libssh2.libssh2_sftp_close(handle)
