```
 ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ 
||e |||t |||h |||w |||e |||b |||t |||o |||k |||e |||n ||
||__|||__|||__|||__|||__|||__|||__|||__|||__|||__|||__||
|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|
```

## Format

`ewt = eth.<address>.<payload>.<proof>`

### address

the ethereum public address in plain-text: `"0xabc..."`


### payload

the message to sign: base64UrlEncode("Login to SkyWeaver.net")
* .. lets use ethSignedTypeData(..)



### proof

the ethWallet.signMessage(payload)


## Authorization

http request header:

`Authorization: Bearer <ewt>`



## TODO

1. issued at?

2. expires at?

... we can let the wallet do this signing
and can show the user on login? kinda useful I guess.. they manage it..
