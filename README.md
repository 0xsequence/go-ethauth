```
 ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ 
||e |||t |||h |||w |||e |||b |||t |||o |||k |||e |||n ||
||__|||__|||__|||__|||__|||__|||__|||__|||__|||__|||__||
|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|
```

## Format

`ewt = eth.<address>.<message-payload>.<signature>`


### Address

The account address in hex encoding, ie. '0x9e63b5BF4b31A7F8d5D8b4f54CD361344Eb744C5'.

Note, you should not rely on this value to be correct, you must parse the EWT and validate it
with the library methods provided. The address is included when used to verify smart wallet
based accounts (aka contract-based accounts).


### Message Payload

a base64 encoded JSON object

```typescript
interface EWTMessagePayload {
  iat: number
  exp: number
  n?: number
  typ?: string
  app?: string
  ogn?: string
}
```

Fields:

  * `iat` (required) - Issued at unix timestamp of when the token has been signed/issued
  * `exp` (required) - Expired at unix timestamp of when the token is valid until
  * `n` (optional) - Nonce value which can be used as a challenge number for added security
  * `typ` (optional) - Type of token
  * `app` (optional) - App identifier requesting the issuance of the token
  * `ogn` (optional) - Domain origin requesting the issuance of the token


### Signature

Signature value of the message payload. The signature may be recoverable with ECRecover to
determine the EOA address, or you may have a different encoding such as one used with EIP-1271,
to validate the contract-based account signature.


## Authorization

http request header:

`Authorization: Bearer <ewt>`


## LICENSE

MIT
