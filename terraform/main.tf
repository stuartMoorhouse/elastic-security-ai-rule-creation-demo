terraform {
  required_version = ">= 1.5"
  required_providers {
    ec = {
      source  = "elastic/ec"
      version = "~> 0.9"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    external = {
      source  = "hashicorp/external"
      version = "~> 2.3"
    }
    http = {
      source  = "hashicorp/http"
      version = "~> 3.4"
    }
  }
}

provider "ec" {} # Reads EC_API_KEY from the environment

provider "azurerm" {
  features {}
  # Reads ARM_CLIENT_ID / ARM_CLIENT_SECRET / ARM_SUBSCRIPTION_ID / ARM_TENANT_ID
  # from the environment
}
