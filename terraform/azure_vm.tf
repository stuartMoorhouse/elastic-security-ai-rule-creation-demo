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

# Uses az CLI instead of azurerm_virtual_machine_extension to avoid two provider bugs:
# 1. Failed applies leave a stale extension in Azure that Terraform can't reconcile without
#    a manual import (the provider doesn't clean up partial failures).
# 2. The provider's async polling can return "Unknown" status even when the extension
#    succeeds, requiring a manual import to continue.
# The az CLI handles polling correctly and lets us check/clean state upfront.
resource "null_resource" "elastic_agent" {
  triggers = {
    vm_id = azurerm_windows_virtual_machine.main.id
  }

  provisioner "local-exec" {
    command = <<-SCRIPT
      set -e
      RG="${azurerm_resource_group.main.name}"
      VM="${azurerm_windows_virtual_machine.main.name}"
      EXT="install-elastic-agent"

      STATE=$(az vm extension show \
        --resource-group "$RG" --vm-name "$VM" --name "$EXT" \
        --query provisioningState -o tsv 2>/dev/null || echo "NotFound")
      echo "Extension state: $STATE"

      if [ "$STATE" = "Succeeded" ]; then
        echo "Extension already succeeded — skipping."
        exit 0
      fi

      if [ "$STATE" != "NotFound" ]; then
        echo "Removing stale extension (state: $STATE)..."
        az vm extension delete --resource-group "$RG" --vm-name "$VM" --name "$EXT"
      fi

      SETTINGS=$(mktemp)
      trap "rm -f $SETTINGS" EXIT
      printf '%s' "$PROTECTED_SETTINGS" > "$SETTINGS"

      az vm extension set \
        --resource-group "$RG" \
        --vm-name "$VM" \
        --name CustomScriptExtension \
        --publisher Microsoft.Compute \
        --version 1.10 \
        --protected-settings "@$SETTINGS"
    SCRIPT

    environment = {
      PROTECTED_SETTINGS = jsonencode({
        fileUris         = ["${azurerm_storage_blob.install_script.url}${data.azurerm_storage_account_sas.scripts.sas}"]
        commandToExecute = "powershell -ExecutionPolicy Bypass -File install.ps1 -ElasticVersion \"${data.ec_stack.latest.version}\" -FleetUrl \"${local.fleet_url}\" -EnrollmentToken \"${local.enrollment_token}\""
      })
    }
  }
}
