# Storage account to host the VM provisioning script. The blob URL + SAS token
# is passed to the CustomScriptExtension via fileUris, avoiding the Windows
# command-line length limit that blocks large -EncodedCommand payloads.

resource "random_id" "storage_suffix" {
  byte_length = 4
}

resource "azurerm_storage_account" "scripts" {
  # Storage account names: 3-24 chars, lowercase alphanumeric only.
  name                            = "${lower(substr(replace(var.prefix, "-", ""), 0, 16))}${random_id.storage_suffix.hex}"
  resource_group_name             = azurerm_resource_group.main.name
  location                        = azurerm_resource_group.main.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
  tags                            = local.tags
}

resource "azurerm_storage_container" "scripts" {
  name                  = "scripts"
  storage_account_name  = azurerm_storage_account.scripts.name
  container_access_type = "private"
}

resource "azurerm_storage_blob" "install_script" {
  name                   = "install.ps1"
  storage_account_name   = azurerm_storage_account.scripts.name
  storage_container_name = azurerm_storage_container.scripts.name
  type                   = "Block"
  source_content         = local.install_script_rendered
}

# Account-level SAS (object scope only) for the extension to download the blob.
# Expires 2030; rotate by tainting this data source and re-applying.
data "azurerm_storage_account_sas" "scripts" {
  connection_string = azurerm_storage_account.scripts.primary_connection_string
  https_only        = true
  signed_version    = "2022-11-02"

  resource_types {
    service   = false
    container = false
    object    = true
  }

  services {
    blob  = true
    queue = false
    table = false
    file  = false
  }

  start  = "2026-01-01T00:00:00Z"
  expiry = "2030-12-31T00:00:00Z"

  permissions {
    read    = true
    write   = false
    delete  = false
    list    = false
    add     = false
    create  = false
    update  = false
    process = false
    tag     = false
    filter  = false
  }
}
