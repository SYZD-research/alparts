# Evidence trace: F-KEY-001 retired-epoch delivery gap

Code-traced on commit e4766f2277d7212d4de66a39df41eb3dcb6abd45.

## Fetch path — key.service.ts getDeviceChannelKeys (~L263-289)

Returns wraps only when ANY of:
1. epoch status is mutable (pending/active) — mutable versions set
2. delivery id is in the caller's accepted-delivery-id list
3. legacy protocol-v1 rows

A retired epoch is excluded from (1); a device that never accepted a delivery
has no id for (2); (3) does not apply to epoch-scoped wraps.

## Mutation path — delivery insert (~L660)

Adding a delivery to a retired epoch is rejected (status check).

## Transition path — epoch retirement

On activation of a successor epoch, the prior epoch's status becomes `retired`.
Recipients that were offline and never fetched the wrap keep a persisted
`channel_keys` row that no API path can return afterward.

## Result

Persisted wrap exists (channel_keys row) + no reachable fetch path = data
loss for the legitimate recipient; unrecoverable if it is the user's only
device.
