# Fleet enrollment automation.
#
# Runs after the Elastic Cloud deployment exists: authenticates to Kibana,
# creates (or reuses) a Fleet agent policy, and resolves an enrollment token
# plus the real Fleet Server URL. See scripts/setup-fleet-policy.sh for the
# actual API calls and the CRITICAL note on why the Fleet Server URL is
# fetched via /api/fleet/fleet_server_hosts rather than read off the
# ec_deployment `integrations_server` attribute (that's the APM endpoint).

data "external" "fleet_setup" {
  program = ["bash", "${path.module}/scripts/setup-fleet-policy.sh"]

  query = {
    kibana_url  = ec_deployment.main.kibana.https_endpoint
    username    = ec_deployment.main.elasticsearch_username
    password    = ec_deployment.main.elasticsearch_password
    policy_name = "${var.prefix}-windows-endpoint-policy"
  }
}

locals {
  fleet_url        = data.external.fleet_setup.result.fleet_url
  enrollment_token = sensitive(data.external.fleet_setup.result.enrollment_token)
}
