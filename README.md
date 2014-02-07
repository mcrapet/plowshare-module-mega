# mega.co.nz plugin for Plowshare4

- Support shares
- Upload chuck by chunk successffuly not simultianously

## Usage

Account upload (public file):
```shell
$ plowup mega -a me@you.com <file>

# In a (local or remote) folder. Specify leaf name only, no path.
$ plowup mega -a me@you.com --folder=MyBackup <file>
```

Note: Anonymous upload (i.e. ephemeral session) has been disabled by mega in early 2014.

Account upload (private file):
```shell
$ plowup mega -a me@you.com --private <file>
```
