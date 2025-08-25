---
gitea: none
include_toc: true
---

# [PangoSync](https://git.orora.vip/me/pangosync)

 A Dockerized script to automatically create, update, and disable resources and their targets in a [`Pangolin`](https://github.com/fosrl/pangolin) instance based on [`Traefik`](https://github.com/traefik/traefik) labels in Docker Swarm services.

## 🤔 How it Works

The script performs two main functions:

1.  **Initial Sync:** On startup, it scans all running Docker Swarm services. For each service with the appropriate labels, it ensures a corresponding resource and target exist and are correctly configured in Pangolin.
2.  **Event Listening:** After the initial sync, the script listens for Docker Swarm service events (`create`, `update`, `remove`). When an event is detected, it processes the service to create, update, or disable the corresponding Pangolin resource and target in real-time.

The script determines the domain for a service by looking for the following labels in order of priority:
1.  `pangolin.domain`
2.  `traefik.http.routers.*.rule` (extracting the domain from the `Host(...)` rule, multiple `Host(...)` rules are supported)

---

## 🔧 Configuration

The script is configured using environment variables:

| Variable                  | Description                                                                                                | Default         | Required |
| ------------------------- | ---------------------------------------------------------------------------------------------------------- | --------------- | -------- |
| `PANGOLIN_API_URL`        | The base URL for the Pangolin API (e.g., `https://api.example.com/v1`).                                    | `""`            | Yes      |
| `PANGOLIN_API_KEY`        | Your Pangolin API key.                                                                                     | `""`            | Yes      |
| `PANGOLIN_ORG_ID`         | The ID of your organization in Pangolin.                                                                   | `""`            | Yes      |
| `PANGOLIN_SITE_ID`        | The numeric ID of the site in Pangolin.                                                                    | `"1"`           | Yes      |
| `PANGOLIN_DOMAIN_ID_MAP`  | A comma-separated list of `domain_id=domain` pairs (e.g., `domain1=example.com,domain2=example.org`).      | `""`            | Yes      |
| `TRAEFIK_AUTH_MIDDLEWARE` | The name of the Traefik middleware used for authentication. If present on a router, SSO will be enabled.   | `"auth@file"`   | No       |
| `DISABLE_ON_REMOVE`       | If `true`, resources will be disabled in Pangolin when the corresponding service is removed.               | `"true"`        | No       |
| `PANGOLIN_POLL_TIMEOUT`   | Timeout in seconds to wait for the Pangolin API to be healthy on startup. `0` means wait forever.          | `"0"`           | No       |
| `PANGOLIN_POLL_INTERVAL`  | Interval in seconds between Pangolin API health checks on startup.                                         | `"5"`           | No       |
| `DRY_RUN`                 | If `1`, the script will log the actions it would take without actually making any changes.                 | `"0"`           | No       |
| `DEBUG`                   | If `1`, enables verbose debug logging.                                                                     | `"0"`           | No       |

---

## ⚙️ Usage

Deploy this script as a Docker service in your Swarm cluster. It needs access to the Docker socket to listen for events.

Here is an example `docker-compose.yml` snippet:

```yaml

services:
  pangosync:
    image: amit94302/pangosync:latest
    user: root
    environment:
      - PANGOLIN_API_URL=https://api.example.com/v1
      - PANGOLIN_API_KEY=your_api_key
      - PANGOLIN_ORG_ID=your_org_id
      - PANGOLIN_SITE_ID=your_site_id
      - PANGOLIN_SITE_NUM_ID=1
      - PANGOLIN_DOMAIN_ID_MAP=domain1=example.com,domain2=example.org
      - TRAEFIK_AUTH_MIDDLEWARE=my-auth@docker
      - DISABLE_ON_REMOVE=true
      ## OPTIONAL ##
      - DEBUG=0
      - DRY_RUN=0
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    deploy:
      mode: replicated
      replicas: 1
      placement:
        constraints:
          - node.role == manager
```

---

## Supported Labels

The script uses the following Docker service labels to configure Pangolin resources:

| Label                                                      | Description                                                                                                                            |
| ---------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `pangolin.domain`                                          | Explicitly sets the full domain for the Pangolin resource. This takes precedence over domains extracted from Traefik rules.              |
| `pangolin.hostname`                                        | Overrides the hostname used for the Pangolin resource name and target IP. Defaults to the container hostname or a sanitized service name. |
| `pangolin.autosync`                                        | If `traefik.enable` is not `true`, this label must be set to `true` for the service to be processed.                                    |
| `traefik.enable`                                           | If set to `true`, the service will be processed.                                                                                       |
| `traefik.http.routers.<router_name>.rule`                  | The script parses `Host(...)` rules to determine the domain(s) for the service.                                                        |
| `traefik.http.routers.<router_name>.middlewares`           | Used to check for the presence of the authentication middleware to enable/disable SSO on the Pangolin resource.                          |
| `traefik.http.services.<service_name>.loadbalancer.server.port` | Explicitly sets the target port for the Pangolin resource.                                                                             |
| `traefik.http.services.<service_name>.loadbalancer.server.scheme` | Sets the target protocol (`http` or `https`).                                                                                          |

---

## 🚢 CI/CD

Image is built and pushed to:

- Docker Hub: [`amit94302/pangosync`](https://hub.docker.com/r/amit94302/pangosync)
- GitHub Container Registry: [`ghcr.io/amit94302/pangosync`](https://github.com/users/amit94302/packages/container/package/pangosync)

Trigger: On push to `main`

---

## 📄 License

[MIT](LICENSE)