# rbac-validator

## Purpose

Validates that a set of files used for RBAC (defining roles, permissions and actions) are correctly defined (there are not broken references).

Specifically, the tool runs the following checks:
* Actions map 1 to 1 with operationIDs.
* Permissions point to existing actions.
* Roles point to existing permissions.
* Every action is pointed by at least one permission that is also pointed by a role (in other words: check that every action is assigned to at least one role).

## How to use

Run `make tools.validate_rbac` from the `app` directory, or `make tools.run_default` from here. Both
use the RBAC files located in signare/app/include/rbac. `make lint` in the `app` directory depends on
the former, so a pipeline calling that standardised step runs the validator too.

Use `make tools.help` for more info about the command and its flags, and `make unit_test` for this
module's own tests. They are a separate module, so the app module's `unit_test` delegates here.

## Exemptions

The JSON-RPC methods are subject to RBAC but appear in no OpenAPI spec, so their actions have no
operation ID to map onto. `--operationIdInclusionsFilePath` is how they are exempted from the 1 to 1
check, and it points at `include/rbac/actions-manual.yaml`, the file that declares them. Reading the
file rather than restating its contents in a flag means the exemption list cannot drift from the
actions it exempts.

That file is pinned to the published method set by the RBAC coverage tests in
`app/pkg/infra/rpcinfra`, in both directions: every method in `SupportedMethods` has an action that at
least one permission grants, and every entry in the file names a method in `SupportedMethods`. So an
exemption is legitimate exactly when it names a published method, and nothing else can be added. The
tests carry that guarantee rather than this tool because only the Go code knows which methods exist.
