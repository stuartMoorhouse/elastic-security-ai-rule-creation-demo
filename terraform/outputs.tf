output "kibana_url" {
  description = "Kibana URL"
  value       = ec_deployment.main.kibana.https_endpoint
}

output "elasticsearch_url" {
  description = "Elasticsearch endpoint URL"
  value       = ec_deployment.main.elasticsearch.https_endpoint
}

output "elastic_username" {
  description = "Elastic superuser username"
  value       = ec_deployment.main.elasticsearch_username
}

output "elastic_password" {
  description = "Elastic superuser password"
  value       = ec_deployment.main.elasticsearch_password
  sensitive   = true
}

output "vm_public_ip" {
  description = "Public IP address of the Windows VM"
  value       = azurerm_public_ip.main.ip_address
}

output "vm_admin_username" {
  description = "Windows VM admin username"
  value       = var.vm_admin_username
}

output "vm_admin_password" {
  description = "Windows VM admin password"
  value       = random_password.vm_admin.result
  sensitive   = true
}
