variable "cf_user" {
  type = string
}

variable "cf_password" {
  type = string
}

variable "cf_org_name" {
  type = string
}

variable "cf_space_name" {
  type    = string
  default = "test"
}

variable "region" {
  type    = string
  default = "us-east"
}

variable "ferrix_forwarder_client_image" {
  type    = string
  default = "ghcr.io/loafoe/ferrix-forwarder-client:v0.3.0"
}

variable "ferrix_forwarder_server_image" {
  type    = string
  default = "ghcr.io/loafoe/ferrix-forwarder-server:v0.3.0"
}

variable "server_instances" {
  type    = number
  default = 2
}

variable "signing_key" {
  type    = string
  default = ""
  sensitive = true
}