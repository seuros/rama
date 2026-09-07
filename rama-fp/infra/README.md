# rama-fp infra

Fly.io deployment configs for the public rama demo services and supporting scripts.

## Deployment host capacity failures

`could not reserve resource for machine: insufficient memory available to fulfill
request on the current host` means Fly cannot allocate the VM on its physical
host. It is not an application OOM, and increasing `[[vm]].memory` does not fix
the host's lack of capacity. A stopped Machine with a GeoIP volume is tied to
that volume's host; repeated deployments can keep failing on the same Machine
even while other replicas deploy successfully.

CI and the GeoIP rollout update one Machine per app at a time (`--max-concurrent
1`). This limits overlapping updates and the resulting `machine is replacing:
concurrent update in progress` errors when a deployment retries. It does not
resolve a persistent host capacity shortage.

To recover a replica that remains blocked, use Fly's
[volume fork procedure](https://fly.io/docs/volumes/volume-manage/#create-a-copy-of-a-volume-fork-a-volume)
to copy its data to a different host in the same region, then replace the
Machine:

1. Record `fly machine list -a APP --json` and `fly volumes list -a APP --json`.
   Identify the failing Machine and its attached volume from the deployment
   error. Keep healthy replicas running.
2. Fork its volume with placement sized for our VMs:
   `fly volumes fork VOLUME -a APP -r fra --vm-size shared-cpu-1x --vm-memory 256`.
   Wait for the new volume to reach `created` state. The default unique-zone
   placement puts the copy on a different host.
3. Clone the affected Machine onto the copied volume:
   `fly machine clone MACHINE -a APP -r fra --attach-volume NEW_VOLUME:/geoip`.
   A plain clone without `--attach-volume` creates an **empty** volume.
4. Verify the replacement's process group, image, services, and `/geoip` files,
   and confirm it can start and serve requests. Only then remove the old,
   stopped Machine with `fly machine destroy MACHINE -a APP`. Its original
   volume remains available for rollback; retained volumes still incur storage
   charges, so remove them separately once recovery is confirmed.
5. Rerun the failed CI jobs and run `bash scripts/remote-healthcheck.sh` from
   this directory. Check both HTTP and HTTPS; they run in separate process
   groups.

## IP geolocation

The `ip`/`echo`/`fp` services optionally enrich responses with IP geolocation
(MaxMind GeoLite2 + IP2Location LITE, served side-by-side). Opt-in via
`RAMA_IP_GEO_DB`; without it the services run unchanged.

[`geoip_sync.sh`](./scripts/geoip_sync.sh) fetches the databases. It needs three
free credentials:

| Variable                                    | From |
| ------------------------------------------- | ---- |
| `MAXMIND_ACCOUNT_ID` + `MAXMIND_LICENSE_KEY` | <https://www.maxmind.com/en/geolite2/signup> → Manage License Keys |
| `IP2LOCATION_TOKEN`                          | <https://lite.ip2location.com> → account Download page |

```sh
# test locally
./scripts/geoip_sync.sh download ./.geoip
export RAMA_IP_GEO_DB="geolite2=./.geoip/GeoLite2-City.mmdb+./.geoip/GeoLite2-ASN.mmdb;ip2location=./.geoip/IP2Location-LITE-DB11.mmdb"
cargo run -p rama-cli -- serve ip --bind 127.0.0.1:8080

# first-time / full rollout to Fly: per app, in parallel — one `geoip` volume
# per machine, deploy the mount, then push the databases
fly auth login && ./scripts/geoip_sync.sh rollout

# later: just refresh the data on already-mounted volumes
./scripts/geoip_sync.sh sync
```

`rollout` and `sync` run all apps concurrently and retry every Fly call (flyctl's
shared agent can crash under parallelism). The `geoip` mount + `RAMA_IP_GEO_DB`
are declared in each app's `fly.toml`, and the services treat a missing/unsynced
database as "no geo" rather than a startup error — so order is not load-bearing.

> IP2Location LITE caps a token at **5 downloads / 24h**; if that (or any
> download) fails, the script reuses the previously fetched file and carries on.
