# Elastic Defend integration, attached to the same Fleet agent policy the
# Windows VM enrolls into (see fleet_enrollment.tf for that policy). Forced
# into detect-only mode — see scripts/setup-elastic-defend.sh for why.

data "external" "elastic_defend" {
  program = ["bash", "${path.module}/scripts/setup-elastic-defend.sh"]

  query = {
    kibana_url = ec_deployment.main.kibana.https_endpoint
    username   = ec_deployment.main.elasticsearch_username
    password   = ec_deployment.main.elasticsearch_password
    policy_id  = data.external.fleet_setup.result.policy_id
  }
}
