# System integration (Windows Security event log), attached to the same Fleet
# agent policy as Elastic Defend. Provides event 4624/4648 (logon success)
# records that the Elastic Security entity store uses to build user-host access
# relationships — specifically, to link jsmith@example.com to the Windows
# endpoint so the remediation Workflow can look up the correct Fleet agent.

data "external" "system_integration" {
  program = ["bash", "${path.module}/scripts/setup-system-integration.sh"]

  query = {
    kibana_url = ec_deployment.main.kibana.https_endpoint
    username   = ec_deployment.main.elasticsearch_username
    password   = ec_deployment.main.elasticsearch_password
    policy_id  = data.external.fleet_setup.result.policy_id
  }
}
