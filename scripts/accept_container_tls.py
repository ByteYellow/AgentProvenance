#!/usr/bin/env python3
"""Opt-in K3s test of automatic OpenSSL and Go TLS discovery after Pod recreation.

Requires root, Docker, K3s, and locally built TLS fixtures. No explicit TLS library
or executable path is supplied to the sensor. All traffic stays on the test node.
"""
import argparse
import collections
import http.server
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import ssl
import subprocess
import tempfile
import threading
import time
import uuid

from accept_node_capture import wait_for
from accept_sensor_live import Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sensor", default="/usr/local/bin/agentprov-sensor")
    parser.add_argument("--go-client", required=True)
    parser.add_argument("--c-client", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("run as root on a K3s test node")
    suffix = uuid.uuid4().hex[:10]
    image = "agentprov-tls-accept:" + suffix
    kube = ["k3s", "kubectl", "-n", "default"]
    checks, identities, markers = {}, [], []
    report = {"schema_version": "agentprovenance.container_tls_acceptance/v1", "architecture": platform.machine(),
              "kernel": platform.release(), "checks": checks}
    report_path = Path(args.report).resolve()
    report_path.parent.mkdir(parents=True, exist_ok=True)
    pods = []
    with tempfile.TemporaryDirectory(prefix="agentprov-container-tls-") as directory:
        root = Path(directory)
        image_root = root / "image"
        image_root.mkdir()
        shutil.copyfile(args.go_client, image_root / "go-client")
        shutil.copyfile(args.c_client, image_root / "c-client")
        for name in ("go-client", "c-client"):
            (image_root / name).chmod(0o755)
        # Copy the actual node's loader and linked libraries into a scratch
        # container. Different mount namespaces exercise /proc/PID/root paths.
        for client in (args.go_client, args.c_client):
            linked = subprocess.run(["ldd", client], capture_output=True, text=True)
            for library in re.findall(r"(/[^\s()]+)", linked.stdout):
                destination = image_root / library.lstrip("/")
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(library, destination)
                destination.chmod(0o755)
        (image_root / "Dockerfile").write_text("FROM scratch\nCOPY . /\n")
        subprocess.run(["docker", "build", "-q", "-t", image, str(image_root)], check=True, stdout=subprocess.DEVNULL)
        archive = root / "image.tar"
        subprocess.run(["docker", "save", "-o", str(archive), image], check=True)
        subprocess.run(["k3s", "ctr", "images", "import", str(archive)], check=True, stdout=subprocess.DEVNULL)
        nodes = json.loads(subprocess.check_output(kube + ["get", "nodes", "-o", "json"], text=True))
        node = nodes["items"][0]
        node_ip = next(address["address"] for address in node["status"]["addresses"] if address["type"] == "InternalIP")
        cert, key = root / "cert.pem", root / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
                        "-days", "1", "-keyout", str(key), "-out", str(cert)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        server = http.server.ThreadingHTTPServer(("0.0.0.0", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        port = server.server_port
        env = os.environ.copy()
        for variable in ("AGENTPROV_SSL_LIB", "AGENTPROV_GO_TLS_BIN"):
            env.pop(variable, None)
        env["AGENTPROV_AUTO_TLS"] = "true"
        events_path, errors_path = root / "events.jsonl", root / "sensor.err"
        with events_path.open("w") as out, errors_path.open("w") as err:
            sensor = subprocess.Popen([args.sensor], env=env, stdout=out, stderr=err)
        try:
            wait_for(lambda: (sensor.poll(), errors_path.read_text()),
                     lambda state: state[0] is not None or "agentprov-sensor: ready" in state[1], "sensor not ready", 30)
            if sensor.poll() is not None:
                raise RuntimeError(errors_path.read_text())
            for generation in range(2):
                pod = f"agentprov-tls-{suffix}-{generation}"
                pods.append(pod)
                containers = []
                for kind in ("go", "legacy", "ex"):
                    marker = f"container-{suffix}-{generation}-{kind}"
                    markers.append(marker)
                    command = (["/go-client", f"https://{node_ip}:{port}/v1/chat/completions", marker]
                               if kind == "go" else ["/c-client", str(port), kind, marker])
                    containers.append({"name": kind, "image": image, "imagePullPolicy": "Never", "command": command,
                                       "env": [{"name": "AGENTPROV_TLS_START_DELAY_SECONDS", "value": "6"},
                                               {"name": "AGENTPROV_TLS_HOST", "value": node_ip}]})
                manifest = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": pod},
                            "spec": {"nodeName": node["metadata"]["name"], "restartPolicy": "Never", "containers": containers}}
                subprocess.run(kube + ["apply", "-f", "-"], input=json.dumps(manifest), text=True,
                               check=True, stdout=subprocess.DEVNULL)
                result = wait_for(lambda: json.loads(subprocess.check_output(kube + ["get", "pod", pod, "-o", "json"], text=True)),
                                  lambda value: value.get("status", {}).get("phase") in ("Succeeded", "Failed"),
                                  "TLS fixtures did not finish", 90)
                checks[f"generation_{generation}:clients_succeeded"] = result["status"]["phase"] == "Succeeded"
                identities.append({status["name"]: status["containerID"].split("://")[-1]
                                   for status in result["status"].get("containerStatuses", [])})
                subprocess.run(kube + ["delete", "pod", pod, "--wait=true", "--timeout=30s"], check=True, stdout=subprocess.DEVNULL)
                # Ensure the first generation's processes disappear through a
                # complete discovery sweep before new container roots appear.
                time.sleep(5)
        finally:
            if sensor.poll() is None:
                sensor.send_signal(signal.SIGINT)
                try:
                    sensor.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    sensor.kill()
                    sensor.wait()
            server.shutdown()
            server.server_close()
            if pods:
                subprocess.run(kube + ["delete", "pod"] + pods + ["--ignore-not-found", "--wait=false"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["k3s", "ctr", "images", "rm", "docker.io/library/" + image], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["docker", "image", "rm", image], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        rows = [json.loads(line) for line in events_path.read_text().splitlines()]
        for generation, ids in enumerate(identities):
            for kind, container_id in ids.items():
                marker = f"container-{suffix}-{generation}-{kind}"
                for direction in ("tls_write", "tls_read"):
                    matching = [row for row in rows if row.get("event_type") == direction and marker in row.get("data", "")
                                and row.get("container_id") == container_id]
                    checks[marker + ":" + direction] = bool(matching)
                    checks[marker + ":" + direction + ":single_chunk"] = len(matching) == 1
        checks["two_container_generations"] = len(identities) == 2 and all(identities[0][kind] != identities[1][kind] for kind in identities[0])
        capabilities = [json.loads(line.split("capabilities ", 1)[1]) for line in errors_path.read_text().splitlines()
                        if line.startswith("agentprov-sensor: capabilities ")]
        probes = [probe for item in capabilities for probe in item["probes"]]
        checks["automatic_discovery_enabled"] = bool(capabilities) and capabilities[-1]["tls_discovery"]["enabled"]
        checks["go_read_reported_attached"] = any("Read" in probe["name"] and probe["status"] == "attached" for probe in probes)
        checks["sensor_clean_exit"] = sensor.returncode == 0
        report.update(container_ids=identities, capability_reports=len(capabilities),
                      final_capabilities=capabilities[-1] if capabilities else None,
                      fixture_event_types=dict(collections.Counter(row.get("event_type") for row in rows if
                          row.get("container_id") in {cid for group in identities for cid in group.values()})),
                      passed=all(checks.values()))
        report_path.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    if not report["passed"]:
        raise SystemExit("FAIL: " + ", ".join(name for name, value in checks.items() if not value))


if __name__ == "__main__":
    main()
