# Telematics scope: what OptiRadar knows, what OptiNexus carries, what is exposed (A10)

Status: inventory and additive read model v1 implemented in OptiRadar. The OptiNexus gateway and OptiFleet are not
changed here (see "Contract gaps for OptiNexus"). Evidence is by code reading unless a test is named.

## 1. Inventory

Position (OptiRadar, `model/Position.java`) and the device report it comes from:

| Field | Stored as | Unit in OptiRadar | Meaning / trap |
|---|---|---|---|
| `fixTime` | timestamp | UTC | When the location was fixed. A report **without a new fix** repeats the previous fix time (`OutdatedHandler`), so it is not the time of the other values. |
| `deviceTime` | timestamp | UTC | The device clock when it sent this report. Time of the attributes (odometer, ignition, ...). |
| `serverTime` | timestamp | UTC | When OptiRadar received it. |
| `valid`, `accuracy` | bool, number | metres | Fix quality. `outdated` is **not stored** (not visible later). |
| `latitude`, `longitude`, `altitude` | number | degrees, metres | Primitive doubles: `0.0` also means "never fixed" (`fixTime` = start of GPS time). |
| `speed`, `course` | number | **knots**, degrees | Not km/h. |
| `attributes.odometer` | number | **metres** | Device odometer. |
| `attributes.totalDistance` | number | **metres** | Distance OptiRadar added up from GPS since the device was added. |
| `attributes.hours` | number | **milliseconds** | Engine hours. |
| `attributes.ignition`, `motion` | bool | - | |
| `attributes.batteryLevel`, `fuelLevel` | number | percent | |
| `attributes.fuel` | number | litres | |
| `attributes.power`, `battery` | number | volts | |
| Device: `status`, `lastUpdate`, `positionId`, `groupId`, `uniqueId`, `name` | | | `status` is online/offline/unknown by `status.timeout`. |

Absent attributes are absent: `Position.getDouble(key)` returns `0.0` for them, which makes "no odometer" look like
zero (`PositionUtil.calculateDistance` even tests `!= 0.0`). The read model never uses that accessor.

OptiRadar never moves a device's latest position back: `PostProcessHandler` only replaces it when the new fix time is
not older. Outbound events to OptiNexus (`optiradar.device.online|offline|overspeed`, `geofence.entered|exited`) are a
separate, transactional-outbox channel and unchanged.

OptiNexus gateway today (`routes/api_gateway.php`, `GatewayService`, `OptiRadarConnector`): one data type, odometer
readings `{device_ref, odometer_km, recorded_at, odometer_kind(DEVICE_ODOMETER|GPS_DISTANCE), device_name,
registration_number}`; the connector polls `/api/groups`, `/api/devices`, `/api/positions` every minute, derives the
tenant itself from the group attribute and sends one reading per device with `recorded_at = fixTime`.

## 2. Findings

| Id | Finding | Evidence | Status |
|---|---|---|---|
| T1 | `recorded_at` is the fix time, and the gateway drops a reading with the same `(tenant, source, device_ref, recorded_at)` as a duplicate. A device that keeps reporting a changing odometer without a new fix repeats the fix time, so the **newer odometer is silently dropped**. | OptiNexus `OptiRadarConnector.php:62`, `GatewayService.php:62-68`; OptiRadar `OutdatedHandler.java:41` | CONFIRMED (code). Radar side fixed by `measured_at`; gateway side is a contract gap. |
| T2 | No `received_at`, no age, no stale marker: a reading from a device that went silent an hour ago looks current. | `GatewayController::ingestReadings` validation | FIXED_AND_TESTED in the read model (`received_at`, `age_seconds`, `stale`). |
| T3 | Units are implicit (km only) and the conversion happens in the consumer (`bcadd(bcdiv(...))`); speed, hours and distances in OptiRadar are knots, ms and metres. | `OptiRadarConnector.php:73-76` | FIXED_AND_TESTED: every value carries `unit`, exact decimal conversion. |
| T4 | The feed looks like a history but is a **sample of the latest state once per poll**; nothing in OptiRadar or the gateway stores a continuous series for it. | `OptiRadarConnector::sync`, no history table in OptiRadar for this | FIXED in wording: the read model says `history: not_provided`; no history is stored or implied. |
| T5 | The tenant is re-derived by the connector walking groups from `/api/groups`. | `OptiRadarConnector.php:100-117` | FIXED_AND_TESTED: OptiRadar states `tenant_id` from device ownership (`DeviceTenants`, nearest group; no tenant, not exported). |
| T6 | Absent values: the connector skips a device without an odometer (good), but nothing prevents a consumer from zero-filling other fields. | - | FIXED_AND_TESTED: absent values are omitted; a device that never reported has `latest: null`; never-fixed devices have no `location`. |
| T7 | Quality of a fix (`valid`, `accuracy`) and the source of the time are not available to consumers. | - | FIXED_AND_TESTED (`location.valid`, `time_source`). |
| T8 | Only the odometer is available through the gateway; other products have no vehicle state (ignition, hours, fuel, status) from OptiRadar. | `api_gateway.php` | PROPOSED: see the scope matrix, needs owner decision. |

## 3. Read model v1: `GET /api/telematics/v1/latest`

Schema `optiradar.telematics.latest`, `schema_version` `1.0`. Read only. Who may call: a tenant user holding
`optiradar.live.view`, the native administrator, and a read-only integration account named in `governance.integrationUsers`
(the OptiNexus connector). The tenant of an entry is
the tenant on the device's group (or the nearest ancestor); it is never taken from the request.

Every caller sees what its links give it (like `/api/devices` without `all=true`); there is no "all devices" switch.

Parameters: `after` (last `device_ref` of the previous page, default 0), `limit` (1-1000, default 500), `include=location`
(coordinates, speed, course; **off by default**), `tenant_id` (a UUID; only narrows what the caller may already read).
Pages are ordered by device id; `next_cursor` is null on the last page.

```json
{ "schema": "optiradar.telematics.latest", "schema_version": "1.0", "source": "optiradar",
  "generated_at": "2026-10-17T10:00:00Z",
  "semantics": { "state": "latest_per_device", "history": "not_provided",
                 "ordering": "keep the larger (measured_at, position_id) per device_ref",
                 "absent_values": "omitted, never zero-filled" },
  "stale_after_seconds": 900, "next_cursor": null, "skipped": { "no_tenant": 2 },
  "items": [ { "device_ref": "12", "unique_id": "35...", "name": "B 1234 XYZ", "tenant_id": "0b1f...",
    "registration_number": "B 1234 XYZ", "device_status": "online", "last_update": "...Z",
    "latest": { "position_id": 9001, "measured_at": "...Z", "time_source": "device", "received_at": "...Z",
      "fix_time": "...Z", "age_seconds": 20, "stale": false,
      "metrics": { "odometer": { "value": "123456.789", "unit": "km", "kind": "DEVICE_ODOMETER" },
                   "gps_distance": { "value": "98765.432", "unit": "km", "kind": "GPS_DISTANCE" },
                   "engine_hours": { "value": "1.500", "unit": "h" }, "ignition": true,
                   "battery_level": { "value": "87.5", "unit": "percent" } },
      "location": { "latitude": -6.2, "longitude": 106.8, "valid": true, "speed_kmh": "18.52", "course_deg": "90.0" } } } ] }
```

Rules (all covered by `TelematicsSnapshotTest`, 20 tests):

* **Times.** `measured_at` is the device report time (`time_source` `device`), else the fix time (`fix`), else the receive
  time (`server`, said so). `received_at` is when OptiRadar got it; `fix_time` is only present when the device ever had a fix.
  `age_seconds` is never negative; a device clock more than 5 minutes ahead adds `clock_ahead: true`.
* **Stale.** `stale = age_seconds > stale_after_seconds` (`telematics.staleSeconds`, default 900). It labels, it never drops.
* **Order and late data.** OptiRadar keeps the newest fix as the device's latest. A consumer keeps, per `device_ref`, the entry
  with the larger `(measured_at, position_id)` and ignores an entry that is older than what it holds.
* **Units and exactness.** `km`, `h`, `L`, `V`, `percent`, `km/h` are stated; metres, milliseconds and knots are converted with
  decimal arithmetic (fixed scale, half-up); values come back as decimal **strings**. Negative, non-numeric, infinite or
  out-of-range values are omitted. A real zero is kept.
* **Latest vs history.** One entry per device, the latest state. No history is stored for this model and none is implied; a
  consumer that polls gets samples, not a continuous series, and must not compute trips or distances between samples from it.
* **Compatibility.** Additive only within `1.x`: fields may be added; consumers ignore unknown fields. A removed or
  re-meant field needs `/v2/`. `schema_version` is in every answer.

## 4. Scope matrix (proposal)

Class A is vehicle state with low sensitivity; class B identifies where a person is.

| Data | Class | Read model v1 | OptiNexus gateway today | Proposed to other products | Needs owner decision |
|---|---|---|---|---|---|
| Odometer (device) / GPS distance, `measured_at`, kind | A | yes | yes (odometer only) | OptiFleet: yes (existing) | no |
| Engine hours, ignition, battery, fuel level, voltages | A | yes | no | OptiFleet maintenance (hours-based) | yes: which products receive them |
| Device status, last update, staleness | A | yes | no | OptiFleet: yes | yes |
| Latest location, speed, course | B | only with `include=location` | no | none by default | **yes**: purpose, retention, who (driver privacy) |
| History (trips, tracks, series) | B | not provided | no | none | **yes** (storage and retention, not in this model) |
| Events (online/offline/overspeed/geofence) | A/B | n/a (outbox, unchanged) | via events API | existing | no |

## 5. Contract gaps for OptiNexus (not changed from here)

1. Ingest keys readings on `recorded_at`: use the device report time (`measured_at`) or key on `position_id`, so a newer
   odometer with an unchanged fix time is not treated as a duplicate (T1).
2. Accept and keep `received_at`/`measured_at`, `unit` and a stale flag next to `odometer_km`; document that the feed is a
   sample of the latest state (T2, T4).
3. Let the connector read `/api/telematics/v1/latest` instead of three raw endpoints and its own group walk (T5, T3).
4. Any new gateway data type (hours, ignition, status) follows "Adding a new gateway data type" (contract, scope, routes,
   service, tests) after the owner decides who receives it (T8).

## 6. Owner decisions needed

* D-T1: may location, speed and course leave OptiRadar for another product, for which purpose, under which retention.
  Default today: not included (`include=location` is opt-in and only for callers who can already read positions).
* D-T2: which class A metrics other products receive (hours, ignition, fuel, status) and through which scope.
* D-T3: whether a history/series is wanted (needs storage design and retention; this model deliberately has none).
* Technical default, not a business decision: `telematics.staleSeconds` = 900.
