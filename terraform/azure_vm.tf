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
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  size                = var.vm_size
  admin_username      = var.vm_admin_username
  admin_password      = random_password.vm_admin.result

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
  # Rendered install script stays lean on purpose: it is embedded directly
  # into the CustomScriptExtension's commandToExecute (via -EncodedCommand),
  # so keeping it well under 16KB avoids any risk of hitting Windows/Azure
  # command-length limits.
  install_script_rendered = templatefile("${path.module}/scripts/install-elastic-agent.ps1.tftpl", {
    elastic_version  = data.ec_stack.latest.version
    fleet_url        = local.fleet_url
    enrollment_token = local.enrollment_token
  })

  # PowerShell's -EncodedCommand expects Base64 of UTF-16LE, not UTF-8 —
  # textencodebase64's second argument handles that directly, so no manual
  # quoting/escaping of the script content is needed at all.
  install_command = "powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand ${textencodebase64(local.install_script_rendered, "UTF-16LE")}"
}

resource "azurerm_virtual_machine_extension" "elastic_agent" {
  name                       = "install-elastic-agent"
  virtual_machine_id         = azurerm_windows_virtual_machine.main.id
  publisher                  = "Microsoft.Compute"
  type                       = "CustomScriptExtension"
  type_handler_version       = "1.10"
  auto_upgrade_minor_version = true

  # commandToExecute carries the enrollment token, so it belongs in
  # protected_settings (encrypted at rest by Azure, marked sensitive by the
  # provider) rather than the plaintext `settings` field.
  protected_settings = jsonencode({
    commandToExecute = local.install_command
  })
}
