# JSON RPC API Specification

This section describes the different JSON RPC API endpoints.

The target audience of this document are users that want to interact with the signare.

RBAC considerations are out of scope of this document. For more details about RBAC, please check
its [documentation](rbac.md){:target="_blank"}.

## Initial considerations

The signare JSON RPC API follows the [JSON-RPC 2.0 Specification](https://www.jsonrpc.org/specification){:target="_
blank"}

The application always responds with a 200 OK HTTP status code, as the error details are part of the JSON RPC response.

Returned JSON RPC errors follow the JSON-RPC 2.0 specification. However, the specification reserves `-32000` to `-32099`
for implementation-defined server errors. Signare defines the following ones:

| Code   | Message             | Description                                                 |
|--------|---------------------|-------------------------------------------------------------|
| -32097 | Precondition failed | The request can not be executed in the current system state |
| -32098 | Not found           | The specified resource was not found.                       |
| -32099 | Unauthorized        | The request was not authorized.                             |
| -32605 | Already exists      | The specified resource already exists.                      |

## Ethereum JSON RPC API supported methods

### eth_signTransaction

The `eth_signTransaction` method is supported following the [Ethereum JSON-RPC API](https://ethereum.org/developers/docs/apis/json-rpc/#eth_signtransaction) specification.

Please, refer to Ethereum's documentation for details about its input and output parameters.

The following transaction types are supported. The type is inferred from the combination of fields present in the request body (there is no explicit `type` field):

| Transaction type      | How it is inferred                                                                                        |
|-----------------------|-----------------------------------------------------------------------------------------------------------|
| Legacy (Type 0)       | `gasPrice` is set (or no gas fields are set) and no `accessList` is set                                   |
| EIP-2930 (Type 1)     | `accessList` is set (an empty accessList is valid), together with `gasPrice` or with no gas fields at all |
| EIP-1559 (Type 2)     | `maxFeePerGas` and `maxPriorityFeePerGas` are set; `accessList` is optional                               |

Combining `gasPrice` with EIP-1559 fields (`maxFeePerGas`/`maxPriorityFeePerGas`) is ambiguous and is rejected with an invalid params error.

!!! info
    If the ``gasPrice`` field of the request body is not informed, it is set to 0.

### eth_signTypedData

Typed structured data hashing and signing is laid out by [EIP-712](https://eips.ethereum.org/EIPS/eip-712).

EIP-712 outlines a procedure for hashing and signing typed structured data as opposed to just byte strings. A new RPC end-point for the JSON-RPC method, `eth_signTypedData`, is included in the ETH-JSON-RPC standard, that is made available to EVM clients. The method parallels `eth_sign`.

The JSON-RPC method `eth_signTypedData` calculates an Ethereum specific signature with: `sign(keccak256("\x19\x01" ‖ domainSeparator ‖ hashStruct(message)))`, as defined in the EIP, with input parameters:

| Property    | Type                      | Description                                         |
|-------------|---------------------------|-----------------------------------------------------|
| address	   | 20 byte address           | Address of the account that will sign the messages. |
| typedData	 | Typed and structured data | Data to be signed.                                  |

Typed data is defined as a JSON object containing type information, domain separator parameters and the message object. 
Below is the JSON schema definition for the `TypedData` param.
```
{
  type: 'object',
  properties: {
    types: {
      type: 'object',
      properties: {
        EIP712Domain: {type: 'array'},
      },
      additionalProperties: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            name: {type: 'string'},
            type: {type: 'string'}
          },
          required: ['name', 'type']
        }
      },
      required: ['EIP712Domain']
    },
    primaryType: {type: 'string'},
    domain: {type: 'object'},
    message: {type: 'object'}
  },
  required: ['types', 'primaryType', 'domain', 'message']
}
```

If the `typedData` `domain` declares a `chainId`, it must equal the application's configured default chain ID; a differing value is rejected with an invalid params error. When the `domain` omits `chainId`, the typed data is signed as provided and the resulting signature is not bound to a chain (the application default chain ID is not injected into the domain separator). Integer message fields larger than 2^53 must be passed as strings (decimal or `0x`-prefixed hex) to avoid loss of precision.

* Success response:

  The hex-encoded signature over the EIP-712 typed data.

    ```
    {"jsonrpc":"2.0","id":1,"result":"0x4355c47d63924e8a72e509b65029052eb6c299d53a04e167c5775fd466751c9d07299936d304c153f6443dfa05f40ff007d72911b6f72307f996231605b915621c"}
    ```

## Custom RPC methods

### eth_generateAccount

Generates a new key pair in the HSM slot configured for the application sent in the header and returns the Ethereum
address that corresponds to the public key.

* Request:

  It does not receive any parameters.

  Example:
    ```
    curl -X POST -H "X-Auth-UserId: <user>" -H "X-Auth-ApplicationId: <application>" --data '{"jsonrpc":"2.0","method":"eth_generateAccount","params":[], "id":1}' http://localhost:4545
    ```

* Success response:

  Example:
    ```
    {"jsonrpc":"2.0","id":1,"result":"0xcc753268336A33e56Da47500D9C786077CC24311"}
    ```

* Error responses:

  | Code   | Message             |
  |--------|---------------------|
  | -32602 | Invalid params      | 
  | -32603 | Internal error      | 
  | -32097 | Precondition failed |
  | -32099 | Unauthorized        |

### eth_importAccount

Imports a private key into the HSM slot configured for the application (only supported for Local Key Vault HSM kind) and
returns the Ethereum
address that derives from its public key.

* Request:

  Input parameters:

  | Name       | Type   | Required |
  |------------|--------|----------|
  | privateKey | string | ✔        |

  Example:
    ```
    curl -X POST -H "X-Auth-UserId: <user>" -H "X-Auth-ApplicationId: <application>" --data '{"jsonrpc":"2.0","method":"eth_importAccount","params":[{"privateKey": "6d36964f44cf2a57968238b5bead10bee82a37e21cdd3e875e4a29d572c1d205"}], "id":1}' http://localhost:4545
    ```

* Success response:

  Example:
    ```
    {"jsonrpc":"2.0","id":1,"result":"0x56cDb4eE596BA7b055B75077794Dd1F408ee150F"}
    ```

* Error responses:

  | Code   | Message             |
  |--------|---------------------|
  | -32605 | Already exists      | 
  | -32602 | Invalid params      | 
  | -32603 | Internal error      | 
  | -32097 | Precondition failed |
  | -32099 | Unauthorized        |

### eth_removeAccount

Removes a key pair from the HSM slot configured for the application sent in the header given the address of the public
key.

* Request:

  Input parameters:

  | Name    | Type   | Required |
  |---------|--------|----------|
  | address | string | ✔        |

  Example:
    ```
    curl -X POST -H "X-Auth-UserId: <user>" -H "X-Auth-ApplicationId: <application>" --data '{"jsonrpc":"2.0","method":"eth_removeAccount","params":[{"address": "0xcc753268336A33e56Da47500D9C786077CC24311"}], "id":1}' http://localhost:4545
    ```

* Success response:

  Example:
    ```
    {"jsonrpc":"2.0","id":1,"result":"0xcc753268336A33e56Da47500D9C786077CC24311"}
    ```

* Error responses:

  | Code   | Message             |
  |--------|---------------------|
  | -32602 | Invalid params      | 
  | -32603 | Internal error      | 
  | -32097 | Precondition failed |
  | -32098 | Not found           |
  | -32099 | Unauthorized        |

### eth_accounts

Lists all the key pairs stored in the HSM slot configured for the application sent in the header as an array of the
Ethereum addresses that correspond to the stored public keys.

* Request:

  It does not receive any parameters.

  Example:
    ```
    curl -X POST -H "X-Auth-UserId: <user>" -H "X-Auth-ApplicationId: <application>" --data '{"jsonrpc":"2.0","method":"eth_accounts","params":[], "id":1}' http://localhost:4545
    ```

* Success response:

  Example:
    ```
    {"jsonrpc":"2.0","id":1,"result":["0xa2c16184fA76cD6D16685900292683dF905e4Bf2","0x13c21AE733fD7312b6dE09a5eb9C5710f8177239","0xcc753268336A33e56Da47500D9C786077CC24311"]}

* Error responses:

  | Code   | Message             |
  |--------|---------------------|
  | -32602 | Invalid params      |
  | -32603 | Internal error      |
  | -32097 | Precondition failed |
  | -32099 | Unauthorized        |
