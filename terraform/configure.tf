resource "terraform_data" "configure" {
  depends_on = [terraform_data.workflow]

  # Re-run when deployment credentials, VM IP, or the configure script itself change.
  input = {
    kibana_url        = ec_deployment.main.kibana.https_endpoint
    elasticsearch_url = ec_deployment.main.elasticsearch.https_endpoint
    vm_public_ip      = azurerm_public_ip.main.ip_address
    script_hash       = filemd5("${path.module}/../scripts/configure.sh")
  }

  provisioner "local-exec" {
    command = "bash '${path.module}/../scripts/configure.sh'"
  }
}
