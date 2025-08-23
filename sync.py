#!/usr/bin/env python3
import os, re, time, json, sys
import requests
import docker

PANGOLIN_API_URL        = os.environ.get("PANGOLIN_API_URL", "").rstrip("/")  # e.g. https://api.example.com/v1
PANGOLIN_API_KEY        = os.environ.get("PANGOLIN_API_KEY", "")
PANGOLIN_ORG_ID         = os.environ.get("PANGOLIN_ORG_ID", "")
PANGOLIN_SITE_ID        = os.environ.get("PANGOLIN_SITE_ID", "")  # NiceId or ID expected by your instance
PANGOLIN_SITE_NUM_ID    = int(os.environ.get("PANGOLIN_SITE_NUM_ID", "1"))
TRAEFIK_AUTH_MIDDLEWARE = os.environ.get("TRAEFIK_AUTH_MIDDLEWARE", "auth@file")  # Traefik authentication middleware
DISABLE_ON_REMOVE       = os.environ.get("DISABLE_ON_REMOVE", "true").lower() in ("1", "true", "yes") # Disable all the resources on service removal
PANGOLIN_POLL_TIMEOUT   = int(os.environ.get("PANGOLIN_POLL_TIMEOUT", "0"))
PANGOLIN_POLL_INTERVAL  = int(os.environ.get("PANGOLIN_POLL_INTERVAL", "5"))
DRY_RUN                 = os.environ.get("DRY_RUN", "0") == "1"
DEBUG                   = os.environ.get("DEBUG", "0") == "1"

docker_env = docker.from_env()
service_cache = {}

if not (PANGOLIN_API_URL and PANGOLIN_API_KEY and PANGOLIN_ORG_ID and PANGOLIN_SITE_ID and PANGOLIN_SITE_NUM_ID):
  print("ERROR: Set PANGOLIN_API_URL, PANGOLIN_API_KEY, PANGOLIN_ORG_ID, PANGOLIN_SITE_ID, and PANGOLIN_SITE_NUM_ID")
  sys.exit(2)

HEADERS = {
  "Authorization": f"Bearer {PANGOLIN_API_KEY}",
  "Content-Type": "application/json",
  "Accept": "*/*",
}

def log(*a): print(*a, flush=True)
def dlog(*a): 
  if DEBUG: print("[DEBUG]", *a, flush=True)

def pangolin_ok():
  try:
    r = requests.get(f"{PANGOLIN_API_URL}/", headers=HEADERS, timeout=10)
    dlog("Health:", r.status_code, r.text[:400])
    return r.ok
  except Exception as e:
    log("ERROR: Pangolin health check failed:", e)
    return False

def wait_for_pangolin(timeout=0, interval=5):
  """Wait until pangolin_ok() returns True, retrying every `interval` seconds."""
  start = time.time()
  while True:
    if pangolin_ok():
      log("Pangolin API is healthy ✅")
      return True
    else:
      log("Waiting for Pangolin API...", PANGOLIN_API_URL)
    
    if timeout and (time.time() - start) > timeout:
      log("Timeout reached while waiting for Pangolin API")
      return False
    time.sleep(interval)

def extract_domains(labels: dict) -> list[str]:
  """
  Try to extract domain from labels.
  Priority:
    1. pangolin.domain label
    2. traefik.http.routers.*.rule label (Host(`domain`))
  """

  domains = []
  if not labels:
    return domains

  # Case 1: dedicated pangolin label
  if "pangolin.domain" in labels:
    domains.append(labels["pangolin.domain"])

  # Case 2: Traefik rule parsing
  for key, value in labels.items():
    if key.startswith("traefik.http.routers.") and key.endswith(".rule"):
      # match *all* Host(`...`) inside the rule string
      matches = re.findall(r"Host\(`([^`]+)`\)", value)
      domains.extend(matches)

  return list(set(domains))  # dedup

def derive_hostname(service, domains: list[str]) -> str:
  labels = service.attrs.get("Spec", {}).get("Labels", {}) or {}

  # 1. explicit override
  if "pangolin.hostname" in labels:
    return labels["pangolin.hostname"]

  # 2. container hostname from swarm spec
  hostname = (
    service.attrs.get("Spec", {})
    .get("TaskTemplate", {})
    .get("ContainerSpec", {})
    .get("Hostname")
  )
  if hostname:
    return hostname

  # 3. fallback to service name without stack prefix
  svc_name = service.name
  if "_" in svc_name:
    return svc_name.split("_", 1)[1]
  
  # 4. subdomain from first domain
  if domains:
    return domains[0].split(".")[0]

  return svc_name

def service_host_published_port(svc):
  # prefer explicit label: traefik.http.services.<name>.loadbalancer.server.port
  labels = svc.attrs.get("Spec", {}).get("Labels", {}) or {}
  name   = svc.name
  explicit = None
  # scan all labels that look like traefik.http.services.*.loadbalancer.server.port
  for k,v in labels.items():
    if k.startswith("traefik.http.services.") and k.endswith(".loadbalancer.server.port") and v:
      explicit = v
      break
  if explicit: 
    return int(explicit)

  # else use first published host port from Endpoint.Spec.Ports (mode: host/ingress)
  ports = (svc.attrs.get("Endpoint", {}) or {}).get("Ports") or []
  for p in ports:
    if p.get("PublishedPort"):
      return int(p["PublishedPort"])
  return None

def split_domain(domain: str):
  """
  Splits a domain into (subdomain, domainId).
  - test.example.com -> ("test", "example.com")
  - foo.bar.example.com -> ("foo", "bar.example.com")
  - example.com -> (None, "example.com")  # apex, skip
  """
  parts = domain.split(".")
  if len(parts) < 3:
      return None, domain  # apex domain -> skip
  subdomain = parts[0]
  domain_id = ".".join(parts[1:])
  return subdomain, domain_id

def list_resources():
  """Fetch all resources for the site and return a list."""
  url = f"{PANGOLIN_API_URL}/site/{PANGOLIN_SITE_NUM_ID}/resources"
  try:
    r = requests.get(url, headers=HEADERS, timeout=20)
  except Exception as e:
    return None, {"status": "network_error", "body": str(e)}

  if not r.ok:
    return None, {"status": r.status_code, "body": r.text}

  try:
    resources = r.json().get("data", {}).get("resources", [])
  except Exception as e:
    return None, {"status": r.status_code, "body": f"Invalid JSON: {e}"}

  return resources, None

def find_resource_by_domain(resources, domain):
  """Find resource in Pangolin by its fullDomain. 
  Returns (exists, resourceId or None)."""
  for res in resources:
    if res.get("fullDomain") == domain:
      return True, res.get("resourceId")
  return False, None

def build_create_payload(name, subdomain, domain_id, site_id):
  """Minimal payload for Pangolin create (PUT)."""
  return {
    "name": name,
    "subdomain": subdomain,
    "siteId": site_id,
    "http": True,
    "protocol": "tcp",
    "domainId": domain_id
  }

def build_update_payload(name, subdomain, domain_id, labels, enabled):
  """Full payload for Pangolin update (POST)."""
  sso_enabled = False
  # Check if any traefik router has auth@file middleware
  for k, v in labels.items():
    if k.startswith("traefik.http.routers.") and k.endswith(".middlewares"):
      middlewares = [m.strip() for m in v.split(",")]
      if TRAEFIK_AUTH_MIDDLEWARE in middlewares:
        sso_enabled = True
        break

  return {
    "name": name,
    "subdomain": subdomain,
    "domainId": domain_id,
    "ssl": True,
    "applyRules": False,
    "sso": sso_enabled,
    "blockAccess": False,
    "emailWhitelistEnabled": False,
    "enabled": enabled
  }

def create_resource(payload):
  """Create a new resource in Pangolin (PUT)."""
  url = f"{PANGOLIN_API_URL}/org/{PANGOLIN_ORG_ID}/site/{PANGOLIN_SITE_NUM_ID}/resource"
  dlog("CREATE", url, "payload:", json.dumps(payload))
  if DRY_RUN:
    log("[DRY-RUN] Would CREATE at", url, "->", json.dumps(payload))
    return True, {"dry_run": True}
  r = requests.put(url, headers=HEADERS, json=payload, timeout=20)
  dlog("PUT", url, "->", r.status_code, r.text[:400])
  if r.ok:
    return True, r.json() if "application/json" in (r.headers.get("Content-Type") or "") else {"ok": True}
  return False, {"status": r.status_code, "body": r.text}

def update_resource(resource_id, payload):
  # Docs show update via POST /v1/resource/:resourceId
  url = f"{PANGOLIN_API_URL}/resource/{resource_id}"
  dlog("UPDATE", url, "payload:", json.dumps(payload))
  if DRY_RUN:
    log("[DRY-RUN] Would UPDATE", url, "->", json.dumps(payload))
    return True, {"dry_run": True}
  r = requests.post(url, headers=HEADERS, data=json.dumps(payload), timeout=20)
  dlog("POST", url, "->", r.status_code, r.text[:400])
  if r.ok:
    return True, r.json() if "application/json" in (r.headers.get("Content-Type") or "") else {"ok": True}
  return False, {"status": r.status_code, "body": r.text}

def sync_targets(resource_id: int, ip: str, method: str, port: int, enabled: bool = True):
  """
  Ensure Pangolin resource targets are correct for given resource_id.
  """
  # Fetch existing targets for a resource
  url = f"{PANGOLIN_API_URL}/resource/{resource_id}/targets"
  r = requests.get(url, headers=HEADERS, timeout=15)
  if not r.ok:
    log(f"ERROR: failed to fetch targets for resource {resource_id} -> {r.status_code} {r.text}")
    return False

  targets = r.json().get("data", {}).get("targets", [])
  payload = {"ip": ip, "method": method, "port": port, "enabled": enabled}

  if not targets:
    # No targets → create new
    if DRY_RUN:
      log(f"[DRY-RUN] Would CREATE target for resource {resource_id}: {json.dumps(payload)}")
      return True

    create_url = f"{PANGOLIN_API_URL}/resource/{resource_id}/target"
    dlog("PUT", create_url, "->", json.dumps(payload))
    r2 = requests.put(create_url, headers=HEADERS, data=json.dumps(payload), timeout=15)
    if r2.ok:
      log(f"CREATED target for resource {resource_id} -> {ip}:{port}")
      return True
    else:
      log(f"FAILED create target {resource_id}: {r2.status_code} {r2.text}")
      return False

  # At least one target exists → update the first one if wrong
  tgt = targets[0]
  if tgt["ip"] != ip or tgt["method"] != method or tgt["port"] != port or tgt["enabled"] != enabled:
    if DRY_RUN:
      log(f"[DRY-RUN] Would UPDATE target {tgt['targetId']} for resource {resource_id}: {json.dumps(payload)}")
      return True
    
    update_url = f"{PANGOLIN_API_URL}/target/{tgt['targetId']}"
    dlog("POST", update_url, "->", json.dumps(desired))
    r2 = requests.post(update_url, headers=HEADERS, data=json.dumps(payload), timeout=15)
    if r2.ok:
      log(f"UPDATED target {tgt['targetId']} for resource {resource_id} -> {ip}:{port}")
      return True
    else:
      log(f"FAILED update target {tgt['targetId']}: {r2.status_code} {r2.text}")
      return False

  log(f"Target already correct for resource {resource_id} -> {method}://{ip}:{port}")
  return True

def listen_swarm_events():
  for event in docker_env.events(decode=True):
    try:
      action = event.get("Action")
      typ = event.get("Type")
      actor = event.get("Actor", {}).get("Attributes", {})

      # Listen only to Swarm services (not every container event)
      if typ == "service" and action in ["create", "update", "remove"]:
        print(f"[EVENT] Service {action}: {json.dumps(actor)}")
        handle_service_event(action, actor)

    except Exception as e:
      print(f"[ERROR] Failed processing event: {e}")

def get_service_with_retry(client, service_name, retries=20, delay=0.5):
  for attempt in range(retries):
    try:
      service = client.services.get(service_name)
      labels = service.attrs.get("Spec", {}).get("Labels", {}) or {}
      return service, labels
    except (docker.errors.NotFound, KeyError):
      time.sleep(delay)
  raise RuntimeError(f"Service {service_name} not ready after {retries} retries")

def handle_service_event(action, attrs):
  service_name = attrs.get("name")
  if not service_name:
    return
  service = service_cache.get(service_name)
  labels = {}

  if not service:
    try:
      service, labels = get_service_with_retry(docker_env, service_name)
      service_cache[service_name] = service
    except RuntimeError as e:
      log(f"[ERROR] Failed to fetch service {service_name}: {e}")
      return
  else:
    labels = service.attrs.get("Spec", {}).get("Labels", {}) or {}
  print(f"Service {service_name} {action} detected")
  # print(f"{labels}")
  
  # domain precedence: explicit > from rule
  domains = extract_domains(labels)  # return a list

  # Get container hostname
  hostname = derive_hostname(service, domains)

  # 1. Derive method from labels
  target_connection_scheme = "http"
  for k, v in labels.items():
    if k.startswith("traefik.http.services.") and k.endswith(".loadbalancer.server.scheme"):
      if v.lower() == "https":
        target_connection_scheme = "https"
      break

  for domain in domains:
    # Get internal container port
    port = service_host_published_port(service)
    if not port:
      log(f"SKIP {hostname}: no host-published port and no explicit traefik service port label")
      continue
    if labels.get("traefik.enable", "").lower() not in ("true", "1", "yes"):
      # Allow opt-in with a label to avoid surprises
      if labels.get("pangolin.autosync", "").lower() not in ("true", "1", "yes"):
        print(f"No labels found for {hostname}. Might be routed using dynamic config file.")
        continue
    resources, err = list_resources()
    if resources is None:
      log(f"ERROR listing resources: {err}")
      return
    exists, resource_id = find_resource_by_domain(resources, domain)
    subdomain, domain_id = split_domain(domain)
    enabled = True
    
    if action in ["create", "update"]:
      try:
        service_cache[service_name] = service  # cache the full spec
        print(f"[{action.upper()}] {service_name} cached")
        # Create resource in Pangolin
        if not exists:
          payload = build_create_payload(hostname, subdomain, domain_id, PANGOLIN_SITE_NUM_ID)
          ok, resp = create_resource(payload)
          if ok:
            log(f"CREATED resource {hostname} -> {domain}")
          else:
            log(f"FAILED create {hostname}: {resp}")
      except docker.errors.NotFound:
        print(f"[WARN] {hostname} not found at {action}")
    elif action == "remove":
      # Mark resource disabled in Pangolin (if DISABLE_ON_REMOVE = true)
      if exists:
        if DISABLE_ON_REMOVE:
          enabled = False
          print(f"Disabling resource for {hostname} -> {domain}")
      service_popped = service_cache.pop(service_name, None)
      if service_popped:
        print(f"[REMOVE] {hostname}: Removing from cache")
      else:
        print(f"[REMOVE] {hostname}: Not found in cache")
      
    # Update resource      
    resources, err = list_resources()
    if resources is None:
      log(f"ERROR listing resources: {err}")
      return
    exists, resource_id = find_resource_by_domain(resources, domain)
    if exists:
      payload = build_update_payload(hostname, subdomain, domain_id, labels, enabled)
      ok, resp = update_resource(resource_id, payload)
      if ok:
        log(f"UPDATED resource {hostname} -> {domain}")
      else:
        log(f"FAILED update {hostname}: {resp}")

    sync_targets(
      resource_id=resource_id,
      ip=hostname,                     # usually the Docker service name or container hostname
      method=target_connection_scheme, # "http" if Traefik routes HTTP, "https" otherwise
      port=port,                       # internal service port
      enabled=True
    )

def sync_services():
  client = docker.DockerClient.from_env()

  services = client.services.list()
  
  for service in services:
    service_name = service.attrs.get("Spec", {}).get("Name")
    service_cache[service_name] = service  # cache the full spec
    labels = service.attrs.get("Spec", {}).get("Labels", {}) or {}
    if labels.get("traefik.enable", "").lower() not in ("true", "1", "yes"):
      # Allow opt-in with a label to avoid surprises
      if labels.get("pangolin.autosync", "").lower() not in ("true", "1", "yes"):
        continue

    # 1. Derive method from labels
    target_connection_scheme = "http"
    for k, v in labels.items():
      if k.startswith("traefik.http.services.") and k.endswith(".loadbalancer.server.scheme"):
        if v.lower() == "https":
          target_connection_scheme = "https"
        break

    # domain precedence: explicit > from rule
    domains = extract_domains(labels)  # return a list
    if not domains:
      print(f"SKIP {service.name}: no domain found in labels")
      continue

    # Get container hostname
    hostname = derive_hostname(service, domains)
    
    # Get internal container port
    port = service_host_published_port(service)
    if not port:
      log(f"SKIP {service.name}: no host-published port and no explicit traefik service port label")
      continue

    for domain in domains:
      resources, err = list_resources()
      if resources is None:
        log(f"ERROR listing resources: {err}")
        return
      # Pangolin often uses a niceId string (frequently the domain) in URL paths
      name = hostname # domain
      exists, resource_id = find_resource_by_domain(resources, domain)

      subdomain, domain_id = split_domain(domain)
      if not subdomain:
        log(f"SKIP {name} -> {domain}: apex domain, no subdomain")
        continue
      if exists:
        # Update resource
        payload = build_update_payload(name, subdomain, domain_id, labels, True)
        ok, resp = update_resource(resource_id, payload)
        if ok:
          log(f"UPDATED resource {name} -> {domain}")
        else:
          log(f"FAILED update {name}: {resp}")
      else:
        # Create and update resource
        payload = build_create_payload(name, subdomain, domain_id, PANGOLIN_SITE_NUM_ID)
        ok, resp = create_resource(payload)
        if ok:
          log(f"CREATED resource {name} -> {domain}")
        else:
          log(f"FAILED create {name}: {resp}")
        
        resources, err = list_resources()
        if resources is None:
          log(f"ERROR listing resources: {err}")
          return
        exists, resource_id = find_resource_by_domain(resources, domain)
        payload = build_update_payload(name, subdomain, domain_id, labels, True)
        ok, resp = update_resource(resource_id, payload)
        if ok:
          log(f"UPDATED resource {name} -> {domain}")
        else:
          log(f"FAILED update {name}: {resp}")
      
      sync_targets(
        resource_id=resource_id,
        ip=hostname,                     # usually the Docker service name or container hostname
        method=target_connection_scheme, # "http" if Traefik routes HTTP, "https" otherwise
        port=port,                       # internal service port
        enabled=True
      )

def main():
  wait_for_pangolin(PANGOLIN_POLL_TIMEOUT, PANGOLIN_POLL_INTERVAL)
  sync_services()
  listen_swarm_events()

if __name__ == "__main__":
  main()
