1. Create an application:
    ```console
    curl --location --request POST 'http://localhost:32325/applications' \
    --header 'X-Auth-UserId: owner' \
    --header 'Content-Type: application/json' \
    --data-raw '{
        "meta": {
            "id": "akv-application"
        },
        "spec": {
            "chainId": "44844"
        }
    }'
    ```

2. Create an application admin user:
    ```console
    curl --location --request POST 'http://localhost:32325/applications/akv-application/users' \
    --header 'X-Auth-UserId: owner' \
    --header 'Content-Type: application/json' \
    --data-raw '{
        "meta": {
            "id": "akv-admin-user"
        },
        "spec": {
            "roles": [
                "application-admin"
            ],
            "description": "a user authorized to administrate an application"
        }
    }'
    ```

3. Create a module:
    ```console
    curl --location --request POST 'http://localhost:32325/admin/modules' \
    --header 'X-Auth-UserId: owner' \
    --header 'Content-Type: application/json' \
    --data-raw '{
        "meta": {
            "id": "akv-hsm-module"
        },
        "spec": {
            "configuration": {
                "hsmKind": "AKV"
            },
            "description": "my first hsm with akv"
        }
    }'
    ```

4. Create a slot:
    ```console
    curl --location --request POST 'http://localhost:32325/admin/modules/akv-hsm-module/slots' \
    --header 'X-Auth-UserId: owner' \
    --header 'Content-Type: application/json' \
    --data-raw '{
        "meta":{
            "id": "akv-hsm-slot"
        },
        "spec": {
            "applicationId": "akv-application",
            "config": {
                "keyName": "<akv key's name to sign>",
                "keyVersion": "<akv key's value to sign>"
            }
        }
    }'
    ```
    

    !!! note
   
         Key name and key version can be obtained through Azure Portal or with Azure CLI.

5. Create a user to sign:
    ```console
    curl --location --request POST 'http://localhost:32325/applications/akv-application/users' \
    --header 'X-Auth-UserId: owner' \
    --header 'Content-Type: application/json' \
    --data-raw '{
        "meta": {
            "id": "akv-user"
        },
        "spec": {
            "roles": [
                "transaction-signer"
            ],
            "description": "a user authorized to sign transactions"
        }
    }'
    ```

6. Enable the account with the AKV key:
    ```console
    curl --location --request POST 'http://localhost:32325/applications/akv-application/users/akv-user/accounts' \
    --header 'X-Auth-UserId: akv-admin-user' \
    --header 'X-Auth-ApplicationId: akv-application' \
    --header 'Content-Type: application/json' \
    --data-raw '{ 
        "spec": {
            "accounts": [
                "<public_address_for_akv_account>"
            ]
        }
    }'
    ```

    !!! note
    
        Public address can be derived from key details obtained by Azure Portal or Azure CLI.

7. Sign a transaction with AKV:
   ```console
   curl --location 'http://localhost:4545' \
   --header 'Content-Type: application/json' \
   --header 'X-Auth-UserId: akv-user' \
   --header 'X-Auth-ApplicationId: akv-application' \
   --data '{
       "id": 1,
       "jsonrpc": "2.0",
       "method": "eth_signTransaction",
       "params": 
           {
            "from": "<public_address_for_akv_account>",
            "to": "0x627306090abaB3A6e1400e9345bC60c78a8BEf57",
            "gas": "0x16760",
            "gasPrice": "0x0",
            "value": "0x1",
            "nonce": "0x0",
            "data": ""
           }
   }' 
   ```
