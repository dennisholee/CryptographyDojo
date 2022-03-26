
### List keys
```sh
gpg --list-keys
/Users/dennislee/.gnupg/pubring.kbx
-----------------------------------
pub   ed25519 2021-09-07 [SC] [expires: 2023-09-07]
      8F9CF560A3DBFA9652AE56F14120A7C4E81D450A
uid           [ultimate] pgpdojo <pgpdojo@pgpdojo.com>
sub   cv25519 2021-09-07 [E] [expires: 2023-09-07]
```

### Export public key

```sh
gpg --armor --export 8F9CF560A3DBFA9652AE56F14120A7C4E81D450A > pubkey.asc
```
