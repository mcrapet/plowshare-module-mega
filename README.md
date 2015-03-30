# mega.co.nz module for Plowshare

This module is more a *proof of concept* of making cryptography with bash
rather than a reliable plugin.

Features:
- Anonymous download
- Anonymous & account upload
  * Support shares
  * Upload chuck by chunk successively not simultaneously
- Folder link listing

Restrictions:
- Account password must not exceed 16 characters

## Usage

Anonymous download:
```shell
# Don't forget to simple quote links
$ plowdown 'https://mega.co.nz/#!EqkzGDoT!E9mAzHvHTsKmORXrzBlstUdGDWxQCMghpng-GoRhRRK'
```

Account upload (public file):
```shell
$ plowup mega -a 'me@you.com' <file>
```

```shell
# In a (local or remote) folder. Specify leaf name only, no path.
$ plowup mega -a 'me@you.com' --folder=MyBackup <file>
```

Note: Anonymous upload (i.e. ephemeral session) has been disabled by mega in early 2014.

Account upload (private file):
```shell
$ plowup mega -a me@you.com --private <file>

# Optional options:
# --nossl    Use HTTP upload url instead of HTTPS
# --eu       Use eu.api.mega.co.nz servers instead of g.api.mega.co.nz
```

Upload process is slow and inefficient because file is cutted into chunks which are uploaded successively.
It's not advised to use with big files.
