terraform {
  required_providers {
    hsdp = {
      source  = "philips-software/hsdp"
      version = "0.65.3"
    }
    cloudfoundry = {
      source  = "cloudfoundry-community/cloudfoundry"
      version = "0.53.1"
    }
  }
}
