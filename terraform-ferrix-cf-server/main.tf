locals {
  signing_key = var.signing_key != "" ? var.signing_key : random_password.signing_key.result
}

resource "random_password" "signing_key" {
  length           = 32
  special          = true
  override_special = "_%@"
}

resource "random_password" "salt" {
  length           = 16
  special          = false
  override_special = "_%@"
}

resource "random_pet" "instance" {
}

resource "hsdp_tenant_key" "key" {
  project      = "ferrix-forwarder"
  organization = "dip"
  signing_key  = random_password.signing_key.result
  expiration   = "2025-12-31T23:59:59Z"
  salt         = random_password.salt.result
}

resource "cloudfoundry_app" "server" {
  name         = "server-${random_pet.instance.id}"
  space        = data.cloudfoundry_space.space.id
  docker_image = var.ferrix_forwarder_server_image
  memory       = 128
  strategy     = "blue-green"
  instances    = var.server_instances

  environment = {
    USERSPACE_PORTFW_SHARED_SECRET = local.signing_key
    USERSPACE_PORTFW_ALLOWED_HOSTS = "" # Empty string to allow all hosts
  }

  routes {
    route = cloudfoundry_route.server.id
  }
}

resource "cloudfoundry_route" "server" {
  domain   = data.cloudfoundry_domain.public.id
  space    = data.cloudfoundry_space.space.id
  hostname = "server-${random_pet.instance.id}"
}
