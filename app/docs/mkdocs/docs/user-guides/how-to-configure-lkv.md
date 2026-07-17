# How to configure a Local Key Vault

This document explains how to configure signare to use a Local Key Vault (or LKV for short).

The target audience of this document is system administrators.

## Introduction

LKV is a local solution designed to store private keys within signare's database. It is our recommended module type to
spin up signare
effortless, and it does not require any prior configuration to start signing transactions. Ideal for local testing and
development
purposes, but not recommended for production environments.

## Configuring a Local Key Vault

This guide assumes that you already have an application and a user configured with the `application-admin` and
`transaction-signer`
roles assigned. Check our [getting started](../getting-started/getting-started.md) section if you need further details.

There are a number of necessary steps prior to sign a transaction with our LKV solution:

1. Configure a new Hardware Security Module (HSM) of type `LocalKeyVault`
    ```console
    curl --location --request POST 'http://localhost:32325/admin/modules' \
    --header 'X-Auth-UserId: owner' \
    --header 'Content-Type: application/json' \
    --data-raw '{
        "meta": {
            "id": "my-id"
        },
        "spec": {
            "configuration": {
                "hsmKind": "LocalKeyVault"
            },
            "description": "my first local key vault"
        }
    }'
    ```
2. Import a valid private key to the LKV. If the imports succeeds, the response will contain it's ethereum address
   ```console
   curl --location 'http://localhost:4545' \
   --header 'X-Auth-UserId: my-user-id' \
   --header 'X-Auth-ApplicationId: my-application-id' \
   --header 'Content-Type: application/json' \
   --data '{
     "id": 1
     "jsonrpc": "2.0",
     "method": "eth_importAccount",
     "params": [
       {
         "privateKey": "5f25e648f40cf86adc5e0a450695acefc4af742da79ab4e62e8db5b65eef21ca"
       }
     ],
    
   }'
   ```
3. Assign the generated address to a user
    ```console
    curl --location --request POST 'http://localhost:32325/applications/my-application-id/users/my-user-id/accounts' \
    --header 'X-Auth-UserId: my-user-id' \
    --header 'X-Auth-ApplicationId: my-application-id' \
    --header 'Content-Type: application/json' \
    --data-raw '{ 
        "spec": {
            "accounts": [
                "<address_generated_in_previous_step>"
            ]
        }
    }'
    ```
   
## Signing a transaction

The user can now sign transaction using its new ethereum address

   ```console
   curl --location 'http://localhost:4545' \
   --header 'X-Auth-UserId: my-user-id' \
   --header 'X-Auth-ApplicationId: my-application-id' \
   --header 'Content-Type: application/json' \
   --data '{
       "id": 1,
       "jsonrpc": "2.0",
       "method": "eth_signTransaction",
       "params": 
           {
            "from": "<user_address>",
            "to": "0x627306090abaB3A6e1400e9345bC60c78a8BEf57",
            "gas": "0x16760",
            "gasPrice": "0x0",
            "value": "0x1",
            "nonce": "0x0",
            "data": ""
           }
   }' 
   ```
