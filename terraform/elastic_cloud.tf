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
