**BETA**

Cryptex manages secure documents for you, stored centrally, and versioned
It is used differently depending upon what you desire to do:

Register an existing remote file:
>```
cryptex -c/--config=NAME [config args]
```

  [config args] are any of:
    --key, --encoder, --versions, --remote, --seed

Add a new file:
>```
cryptex -c/--config=NAME -f/--file=FILE [config args]
```

See existing configuration:
>```
cryptex -c/--config
```

List files:
>```
cryptex -ls/--list
```

Delete a file:
>```
cryptex --delete=NAME
```

View the latest file:
>```
cryptex NAME
```

Search the latest file for MATCH:
>```
cryptex NAME MATCH
```

Edit the latest file:
>```
cryptex NAME --e?dit
```

Other options:
* --force      required for some actions
* -d/--debug=m enable debuging of module (m), may be specified multiple times
               modules: base, remoteFile, http
* --encoder=x  specify an alternate encoder from gpg+vim.  None is acceptable.
* --key=k      specify the key to use with the editor (such as the gpg key)
* --version=v  specify a specific version to view (look at --ls)
* --versions=x specify how many versions to keep with --add, default: 50
* --remote=def specify the remote registry, format:
                    s3://API_KEY:API_SECRET@BUCKET/PATH

Also available are shortcuts: cx and vicx

