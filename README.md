```
 ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ 
||e |||t |||h |||w |||e |||b |||t |||o |||k |||e |||n ||
||__|||__|||__|||__|||__|||__|||__|||__|||__|||__|||__||
|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|
```

**NOTE: in specification stage**

## Format

`ewt = eth.<address>.<payload>.<proof>`


### address

the ethereum public address in plain-text: `"0xabc..."`


### payload

a base64 encoded JSON hash containing information such as:
  * EIP712Domain (https://github.com/ethereum/EIPs/blob/master/EIPS/eip-712.md)
  * Message, ie. "Login to SkyWeaver.net"
  * IssuedAt timestamp
  * ExpiresAt timestamp (optional)


### proof

`proof = eth_signTypedData(payload)`


## Authorization

http request header:

`Authorization: Bearer <ewt>`

