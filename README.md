**ALPHA GRADE FOR THE MOMENT**

> Originally written in python2, conversion to python3 broke some functionality, but mostly it is working.

Cryptex manages secure documents for you, stored centrally, and versioned.

Think of it as a simpler form of one password, lastpass pwsafe and the like.

Install using python3 pip:

>```
    pip install cryptex
```

Usage varies by what you want to do:

Register an existing remote file with s3:
>```
    cryptex --config=NAME --remote=s3://key:secret@s3-bucket/filename --key=generate
```

View the latest file:
>```
    cryptex NAME
```

Edit the latest file:
>```
    cryptex NAME --edit
```
>```
    cryptex NAME -e
```

Also available are shortcuts: cx and vicx

