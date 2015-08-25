SFTP Client using libssh2
=========================

This library exists because sftp downloads in paramiko are sloooooooooowwwwwwwwwww...

It only supports listing and getting files. The bare minimum we needed.

Example::

    with Session((host, port)) as ssh:
        assert ssh.get_md5_fingerprint() == b'whatever dude!!!'  # Binary data, not hex
        # assert ssh.get_sha1_fingerprint() == ...
        ssh.authenticate(username, password)
        with ssh.get_sftp() as sftp:
            dirlist = sftp.listdir('.')
            contents = sftp.get_file_contents(dirlist[0].name)
            # Faster!!!
            contents = sftp.get_file_contents(dirlist[0].name, buffer_size=5 * 2 ** 20)
