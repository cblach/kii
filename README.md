# kii
Command-line password manager written in go using AES-256 to store passwords. It relies heavily on scrypt for key verification and encryption keys.

Basic command examples:
```bash
$ kii genfile
$ kii set google
$ kii get google
$ kii list
```

```
Common flags:
-f PATH         Set the path of the database file. Default is ~/kii.json.

Flags for "kii set":
-u USERNAME     Store username
-l NUMBER       Set a password length
-url            Store the login url
-nosymbols      Only allows letters and numbers in generated passwords
```
