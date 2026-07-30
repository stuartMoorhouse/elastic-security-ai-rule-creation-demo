# Windows Server 2022 VM, enrolled into Elastic Cloud Fleet via a
# CustomScriptExtension. Admin password is generated (never user-supplied).

resource "random_password" "vm_admin" {
  length      = 20
  special     = true
  min_upper   = 2
  min_lower   = 2
  min_numeric = 2
  min_special = 2
  # Restrict to characters Azure accepts for VM admin passwords.
  override_special = "!@#$%*()-_=+[]"
}

resource "azurerm_windows_virtual_machine" "main" {
  name                = "${var.prefix}-vm"
  computer_name       = "secdemo-vm" # Windows computer_name is capped at 15 chars
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  size                = var.vm_size
  admin_username      = var.vm_admin_username
  admin_password      = random_password.vm_admin.result
  tags                = local.tags

  network_interface_ids = [azurerm_network_interface.main.id]

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
  }

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2022-datacenter-azure-edition"
    version   = "latest"
  }
}

locals {
  # Credentials are NOT embedded in the blob — they are passed as parameters
  # via commandToExecute (protected_settings, encrypted by Azure at rest).
  # This keeps the blob content static and avoids command-line length limits.
  install_script_rendered = join("\n", [
    file("${path.module}/scripts/install-elastic-agent.ps1"),
    file("${path.module}/scripts/install-openssh.ps1"),
    file("${path.module}/scripts/create-demo-users.ps1"),
    "exit 0",
  ])
}

resource "azurerm_virtual_machine_extension" "elastic_agent" {
  name                       = "install-elastic-agent"
  virtual_machine_id         = azurerm_windows_virtual_machine.main.id
  publisher                  = "Microsoft.Compute"
  type                       = "CustomScriptExtension"
  type_handler_version       = "1.10"
  auto_upgrade_minor_version = true

  # The script is downloaded from private blob storage (fileUris + SAS token);
  # commandToExecute is short — it only passes the three credential parameters.
  # Both live in protected_settings (encrypted by Azure) to keep the token secret.
  protected_settings = jsonencode({
    fileUris         = ["${azurerm_storage_blob.install_script.url}${data.azurerm_storage_account_sas.scripts.sas}"]
    commandToExecute = "powershell -ExecutionPolicy Bypass -File install.ps1 -ElasticVersion \"${data.ec_stack.latest.version}\" -FleetUrl \"${local.fleet_url}\" -EnrollmentToken \"${local.enrollment_token}\""
  })

  # Don't re-run the install script on already-provisioned VMs. The agent is
  # enrolled and running; re-running the extension when the script changes
  # (new token, version bump, etc.) would try to overwrite locked agent files.
  # Taint this resource manually if a full re-enroll is needed.
  lifecycle {
    ignore_changes = [protected_settings]
  }
}
