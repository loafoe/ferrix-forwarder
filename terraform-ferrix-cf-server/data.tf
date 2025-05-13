data "hsdp_config" "cf" {
  region  = var.region
  service = "cf"
}

data "cloudfoundry_domain" "internal" {
  name = "apps.internal"
}

data "cloudfoundry_domain" "public" {
  name = data.hsdp_config.cf.domain
}

data "cloudfoundry_space" "space" {
  name = var.cf_space_name
  org  = data.cloudfoundry_org.org.id
}

data "cloudfoundry_org" "org" {
  name = var.cf_org_name
}