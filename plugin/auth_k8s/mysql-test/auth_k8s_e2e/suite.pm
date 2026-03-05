package My::Suite::AuthK8sE2e;

@ISA = qw(My::Suite);

use strict;

return "Not run for embedded server" if $::opt_embedded_server;

return "No AUTH_K8S plugin" unless $ENV{AUTH_K8S_SO};

return "kubectl not found"
  unless `sh -c "command -v kubectl"`;

return "No Kubernetes cluster available"
  if system("kubectl cluster-info > /dev/null 2>&1") != 0;

return "Test namespace mariadb-auth-test not found"
  if system("kubectl get namespace mariadb-auth-test > /dev/null 2>&1") != 0;

return "Test ServiceAccount user1 not found in mariadb-auth-test namespace"
  if system("kubectl get sa user1 -n mariadb-auth-test > /dev/null 2>&1") != 0;

# Extract K8s API server URL from kubectl
my $api_server = `kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null`;
chomp $api_server;
if (!$api_server) {
  return "Could not determine Kubernetes API server URL";
}
$ENV{'K8S_API_URL'} = $api_server;

# Extract CA cert path - write the CA data to a temp file if needed
my $vardir = $ENV{'MYSQLTEST_VARDIR'} || '/tmp';
my $ca_file = "$vardir/k8s-ca.crt";
my $ca_data = `kubectl config view --minify --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' 2>/dev/null`;
chomp $ca_data;
if ($ca_data) {
  # Decode base64 CA data and write to file
  open(my $fh, '>', $ca_file) or return "Cannot write CA cert: $!";
  use MIME::Base64;
  print $fh decode_base64($ca_data);
  close $fh;
  $ENV{'K8S_CA_PATH'} = $ca_file;
} else {
  # Try certificate-authority path directly
  my $ca_path = `kubectl config view --minify -o jsonpath='{.clusters[0].cluster.certificate-authority}' 2>/dev/null`;
  chomp $ca_path;
  if ($ca_path && -f $ca_path) {
    $ENV{'K8S_CA_PATH'} = $ca_path;
  } else {
    return "Could not determine Kubernetes CA certificate";
  }
}

# Create a long-lived token for MariaDB server to use for TokenReview API calls.
# The server needs its own SA token to authenticate with the K8s API.
# We create a token for the 'mariadb-tokenreview' SA which has auth-delegator permissions.
my $server_token_file = "$vardir/k8s-server-token";
my $server_token = `kubectl create token mariadb-tokenreview -n mariadb-auth-test --duration=1h 2>/dev/null`;
chomp $server_token;
if (!$server_token) {
  return "Could not create server token for mariadb-tokenreview SA";
}
open(my $fh, '>', $server_token_file) or return "Cannot write server token: $!";
print $fh $server_token;
close $fh;
$ENV{'K8S_TOKEN_PATH'} = $server_token_file;

sub is_default { 1 }

bless {};
