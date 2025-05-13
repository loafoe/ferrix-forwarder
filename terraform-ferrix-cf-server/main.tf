resource "random_password" "password" {
  length           = 32
  special          = true
  override_special = "_%@"
}

resource "random_pet" "instance" {
}

resource "cloudfoundry_app" "server" {
  name         = "server-${random_pet.instance.id}"
  space        = data.cloudfoundry_space.space.id
  docker_image = var.ferrix_forwarder_server_image
  memory       = 128
  strategy     = "blue-green"
  instances    = var.server_instances

  environment = {
    USERSPACE_PORTFW_TOKEN         = random_password.password.result
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
