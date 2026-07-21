# Elastic Cloud (ECH) deployment — hot tier only, small size.
#
# The stack version is resolved to the latest 9.4.x patch via the ec_stack
# data source rather than hardcoded, per project convention.

data "ec_stack" "latest" {
  version_regex = "^9\\.4\\."
  region        = var.ec_region
}

resource "ec_deployment" "main" {
  name                   = "${var.prefix}-ech"
  region                 = var.ec_region
  version                = data.ec_stack.latest.version
  deployment_template_id = var.ec_deployment_template_id

  elasticsearch = {
    hot = {
      size        = var.elasticsearch_size
      zone_count  = var.elasticsearch_zone_count
      autoscaling = {}
    }
  }

  kibana = {
    size       = var.kibana_size
    zone_count = var.kibana_zone_count
  }

  # Provisions Fleet Server automatically. Do NOT use this resource's
  # `integrations_server` endpoint attributes as the Fleet enrollment URL —
  # that surfaces the APM endpoint, not the Fleet Server endpoint. The real
  # Fleet Server URL is resolved separately via the Kibana Fleet API in
  # fleet_enrollment.tf (see /api/fleet/fleet_server_hosts).
  integrations_server = {}
}

# Install the Okta integration package so its ingest pipeline is registered.
# The pipeline maps raw Okta System Log fields to ECS (okta.event_type, user.name, source.ip, etc.).
resource "null_resource" "okta_integration" {
  triggers = {
    deployment_id = ec_deployment.main.id
  }

  provisioner "local-exec" {
    command = <<-EOT
      OKTA_INFO=$(curl -sf \
        -u "${ec_deployment.main.elasticsearch_username}:${ec_deployment.main.elasticsearch_password}" \
        -H "kbn-xsrf: true" \
        "${ec_deployment.main.kibana.https_endpoint}/api/fleet/epm/packages/okta")
      OKTA_VERSION=$(echo "$OKTA_INFO" | jq -r '.item.version // .response.version')
      OKTA_STATUS=$(echo "$OKTA_INFO"  | jq -r '.item.status  // .response.status')
      if [ "$OKTA_STATUS" != "installed" ]; then
        curl -sf \
          -u "${ec_deployment.main.elasticsearch_username}:${ec_deployment.main.elasticsearch_password}" \
          -H "kbn-xsrf: true" -H "Content-Type: application/json" \
          -X POST \
          "${ec_deployment.main.kibana.https_endpoint}/api/fleet/epm/packages/okta/$OKTA_VERSION" \
          -d '{}'
      fi
    EOT
  }
}

# Set the default Kibana space to the Security solution view.
resource "null_resource" "kibana_security_solution" {
  triggers = {
    deployment_id = ec_deployment.main.id
  }

  provisioner "local-exec" {
    command = <<-EOT
      curl -sf \
        -u "${ec_deployment.main.elasticsearch_username}:${ec_deployment.main.elasticsearch_password}" \
        -H "kbn-xsrf: true" \
        -H "Content-Type: application/json" \
        -X PUT "${ec_deployment.main.kibana.https_endpoint}/api/spaces/space/default" \
        -d '{"id":"default","name":"Default","solution":"security"}'
    EOT
  }
}
