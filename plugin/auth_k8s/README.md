# Kubernetes ServiceAccount Authentication Plugin (auth_k8s)

Server-side authentication plugin that validates Kubernetes ServiceAccount
tokens using the TokenReview API.

Clients connect with:
- **Username**: `namespace/serviceaccount` (e.g., `default/myapp`)
- **Password**: Kubernetes ServiceAccount JWT token

The plugin calls the Kubernetes TokenReview API to validate the token and
verify the identity matches the requested username.

## Dependencies

- libcurl (for HTTP requests to K8s API)

The plugin is automatically built when CURL is available. If CURL is not
found, the plugin is skipped.

## Configuration

System variables (set in my.cnf or via command line):

| Variable | Default | Description |
|----------|---------|-------------|
| `auth_k8s_api_url` | `https://kubernetes.default.svc` | Kubernetes API server URL |
| `auth_k8s_ca_path` | `/var/run/secrets/.../ca.crt` | Path to K8s CA certificate |
| `auth_k8s_token_path` | `/var/run/secrets/.../token` | Path to SA token for API auth |
| `auth_k8s_timeout` | `10` | API request timeout in seconds |

When running inside a Kubernetes pod, the defaults work automatically.
For external use, configure the URL and credentials explicitly.

## Usage

```sql
INSTALL SONAME 'auth_k8s';
CREATE USER 'default/myapp' IDENTIFIED WITH auth_k8s;
GRANT SELECT ON mydb.* TO 'default/myapp';
```

Client connects using `mysql_clear_password` client plugin:

```bash
TOKEN=$(kubectl create token myapp -n default)
mysql -u 'default/myapp' -p"$TOKEN" --enable-cleartext-plugin
```

## Running Tests

There are two MTR test suites:

- **`auth_k8s`** — Plugin-only tests (load, sysvars, auth rejection). Always runs.
- **`auth_k8s_e2e`** — End-to-end tests requiring a real Kubernetes cluster. Skips gracefully if no cluster is available.

### Plugin-only tests (no cluster needed)

```bash
cd mysql-test
./mtr --suite=auth_k8s
```

### End-to-end tests with Kind

```bash
# Create Kind cluster with test resources
plugin/auth_k8s/testing/setup-kind-cluster.sh

# Build the server
mkdir build && cd build
cmake .. -DPLUGIN_AUTH_K8S=DYNAMIC
make -j$(nproc)

# Run all tests
cd mysql-test
./mtr --suite=auth_k8s,auth_k8s_e2e
```

### Using an existing cluster

The tests work with any Kubernetes cluster. Set up the required resources:

```bash
kubectl apply -f plugin/auth_k8s/testing/k8s/namespace.yaml
kubectl apply -f plugin/auth_k8s/testing/k8s/rbac.yaml
kubectl apply -f plugin/auth_k8s/testing/k8s/test-clients.yaml
```

The `auth_k8s_e2e` suite will auto-detect the cluster via `kubectl` and
skip if prerequisites are not met.

### Cleanup

```bash
# If using Kind
kind delete cluster --name auth-k8s-test

# If using existing cluster
kubectl delete namespace mariadb-auth-test
kubectl delete clusterrolebinding mariadb-tokenreview
```
