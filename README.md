# mega.co.nz module for Plowshare

This module is more a *proof of concept* of making cryptography with Bash rather than a reliable plugin.

Features:
- Anonymous download
- Anonymous & account upload
  * Support shares
  * Upload chuck by chunk successively not simultaneously
- Folder link listing

Restrictions:
- Account password must not exceed 16 characters

## Usage

### Download

Anonymous download:
```shell
$ plowdown 'https://mega.co.nz/#!EqkzGDoT!E9mAzHvHTsKmORXrzBlstUdGDWxQCMghpng-GoRhRRK'
```

**Note**: Don't forget to simple quote links because `!` is reserved by Bash for history substitution.

#### Ignore CRCs

Concerning file encryption (AES-128-CTR), mega does not check cipher itself but only verify correct *meta-MAC*
(64-bit hash) and well formed data (using AES 128-bit key + 2*32-bit IV). Technically, any symmetric cipher could
be used, even plaintext!

Use `--ignore-crc` switch to ignore *meta-MAC* mismatch: allow to get the file even if *meta-MAC* verification fails.

### Upload

Account upload (public file):
```shell
$ plowup mega -a 'email:password' <file>
```

**Note**: `:` is the separator character for login and password.

```shell
# In a (local or remote) folder. Specify leaf name only, no path.
$ plowup mega -a 'email:password' --folder=MyBackup <file>
```

**Note**: Anonymous upload (i.e. ephemeral session) has been disabled by mega in early 2014.

Account upload (private file):
```shell
$ plowup mega -a 'email:password' --private <file>
```

Optional options:
- `--nossl` : use HTTP upload url instead of HTTPS
- `--eu` : use `eu.api.mega.co.nz` servers instead of `g.api.mega.co.nz`

Upload process is slow and inefficient because file is cut into chunks which are uploaded successively.
It's not advised to use with big files.

### List

Anonymous public folder:
```shell
$ plowlist 'https://mega.co.nz/#F!94wGHLbd!nx8UQbcMZTuFGMhJvFk_ZQ'
```
