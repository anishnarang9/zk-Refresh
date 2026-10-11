# Host admission before selective build002

Parent read-only observations, October 11, 2026. No proof, setup or benchmark executed during this window. Commands were `sysctl kern.memorystatus_vm_pressure_level vm.swapusage` and `vm_stat`, at approximately one-second intervals, with UTC timestamps from the clock tool. Thirty-one samples span 03:23:02–03:23:34 UTC. All pressure values were 1; Swapouts stayed 97,372,983; Swapins rose 84,315,172→84,315,192 (20 compressed pages), with maximum 1 consecutive active interval. Printed swap occupancy stayed 12082.62M. The finite stable-normal admission policy in the population observer proposal is satisfied for a separately granted small build. These observations are not a physical availability guarantee or a ten-state/credential runtime grant.

| UTC | Pressure | Swapins | Swapouts | Printed used swap M |
|---|---:|---:|---:|---:|
| 2026-10-11 03:23:02 UTC | 1 | 84315172 | 97372983 | 12082.62 |
| 2026-10-11 03:23:03 UTC | 1 | 84315172 | 97372983 | 12082.62 |
| 2026-10-11 03:23:04 UTC | 1 | 84315176 | 97372983 | 12082.62 |
| 2026-10-11 03:23:05 UTC | 1 | 84315176 | 97372983 | 12082.62 |
| 2026-10-11 03:23:06 UTC | 1 | 84315176 | 97372983 | 12082.62 |
| 2026-10-11 03:23:07 UTC | 1 | 84315176 | 97372983 | 12082.62 |
| 2026-10-11 03:23:08 UTC | 1 | 84315176 | 97372983 | 12082.62 |
| 2026-10-11 03:23:10 UTC | 1 | 84315176 | 97372983 | 12082.62 |
| 2026-10-11 03:23:11 UTC | 1 | 84315180 | 97372983 | 12082.62 |
| 2026-10-11 03:23:12 UTC | 1 | 84315180 | 97372983 | 12082.62 |
| 2026-10-11 03:23:13 UTC | 1 | 84315180 | 97372983 | 12082.62 |
| 2026-10-11 03:23:14 UTC | 1 | 84315180 | 97372983 | 12082.62 |
| 2026-10-11 03:23:15 UTC | 1 | 84315184 | 97372983 | 12082.62 |
| 2026-10-11 03:23:16 UTC | 1 | 84315184 | 97372983 | 12082.62 |
| 2026-10-11 03:23:17 UTC | 1 | 84315184 | 97372983 | 12082.62 |
| 2026-10-11 03:23:18 UTC | 1 | 84315184 | 97372983 | 12082.62 |
| 2026-10-11 03:23:19 UTC | 1 | 84315184 | 97372983 | 12082.62 |
| 2026-10-11 03:23:20 UTC | 1 | 84315184 | 97372983 | 12082.62 |
| 2026-10-11 03:23:21 UTC | 1 | 84315184 | 97372983 | 12082.62 |
| 2026-10-11 03:23:22 UTC | 1 | 84315184 | 97372983 | 12082.62 |
| 2026-10-11 03:23:24 UTC | 1 | 84315184 | 97372983 | 12082.62 |
| 2026-10-11 03:23:25 UTC | 1 | 84315184 | 97372983 | 12082.62 |
| 2026-10-11 03:23:26 UTC | 1 | 84315184 | 97372983 | 12082.62 |
| 2026-10-11 03:23:27 UTC | 1 | 84315184 | 97372983 | 12082.62 |
| 2026-10-11 03:23:28 UTC | 1 | 84315188 | 97372983 | 12082.62 |
| 2026-10-11 03:23:29 UTC | 1 | 84315188 | 97372983 | 12082.62 |
| 2026-10-11 03:23:30 UTC | 1 | 84315188 | 97372983 | 12082.62 |
| 2026-10-11 03:23:31 UTC | 1 | 84315188 | 97372983 | 12082.62 |
| 2026-10-11 03:23:32 UTC | 1 | 84315188 | 97372983 | 12082.62 |
| 2026-10-11 03:23:33 UTC | 1 | 84315192 | 97372983 | 12082.62 |
| 2026-10-11 03:23:34 UTC | 1 | 84315192 | 97372983 | 12082.62 |
