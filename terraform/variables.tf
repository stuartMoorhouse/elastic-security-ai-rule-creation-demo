variable "region" {
  description = "Azure region for the Windows VM"
  type        = string
  default     = "westeurope"
}

variable "prefix" {
  description = "Resource name prefix"
  type        = string
  default     = "elastic-sec-demo"
}

variable "my_ip" {
  description = "Public IP (CIDR) allowed to RDP into the Windows VM"
  type        = string
}

# --- Elastic Cloud (ECH) ---

variable "ec_region" {
  description = "Elastic Cloud region for the deployment (independent of the Azure VM region)"
  type        = string
  default     = "gcp-europe-west1"
}

variable "ec_deployment_template_id" {
  description = "Elastic Cloud deployment template ID"
  type        = string
  default     = "gcp-storage-optimized"
}

variable "elasticsearch_size" {
  description = "Elasticsearch hot tier size per node, e.g. \"4g\""
  type        = string
  default     = "4g"
}

variable "elasticsearch_zone_count" {
  description = "Number of availability zones for the Elasticsearch hot tier"
  type        = number
  default     = 1
}

variable "kibana_size" {
  description = "Kibana node size, e.g. \"1g\""
  type        = string
  default     = "1g"
}

variable "kibana_zone_count" {
  description = "Number of availability zones for Kibana"
  type        = number
  default     = 1
}

# --- Azure Windows VM ---

variable "vm_size" {
  description = "Azure VM size for the Windows host"
  type        = string
  default     = "Standard_B2s"
}

variable "vm_admin_username" {
  description = "Admin username for the Windows VM"
  type        = string
  default     = "demoadmin"
}
