# Metrics

The signare exposes key metrics to measure its state through a `Prometheus` server. This document describes the complete set of metrics provided by the application.

The target audience of this document are signare operators and developers.

The following metric types are used depending on the value that needs to be measured:

- Counter: Cumulative metric that represents a single monotonically increasing counter.
- Gauge: Metric that represents a single value that can go up and down.

For more details on types of metrics, please refer to [Prometheus metrics documentation](https://prometheus.io/docs/concepts/metric_types/>)

## HTTP metrics

| Name                        | Labels             | Type    | Description                                                     |
|-----------------------------|--------------------|---------|-----------------------------------------------------------------|
| **forbidden_access_count**  | "action", "error"  | counter | Total number of attempts to perform a given unauthorized action |

## HSM metrics

| Name                          | Labels               | Type  | Description                                                       |
|-------------------------------|----------------------|-------|-------------------------------------------------------------------|
| **hsm_slot_pin_breaker_open** | "slot", "moduleKind" | gauge | 1 while a slot is not being retried because its PIN was refused    |

Signare logs in to a token on every operation, so one wrong PIN would otherwise become a failed login
on every signature and an HSM locks the user PIN after a few of those. When a login is refused, Signare
stops attempting that slot and sets this gauge to 1.

It returns to 0 when the file the slot's `pinSource` names changes content, or when
`admin.slots.verifyPinSource` succeeds. **Alert on this being 1**: every signing request for that
application is failing.


## Default GO process metrics exposed by Prometheus GO client library

The default set of metrics that Prometheus’ [client_golang](https://github.com/prometheus/client_golang>) exposes are also exposed by the signare.
