# Outputs for the ferrix-forwarder CloudFlare server deployment

output "server_hostname" {
  description = "The hostname of the deployed ferrix-forwarder server"
  value       = cloudfoundry_route.server.hostname
}

output "server_domain" {
  description = "The domain of the deployed ferrix-forwarder server"
  value       = data.cloudfoundry_domain.public.name
}

output "server_url" {
  description = "The full URL of the deployed ferrix-forwarder server"
  value       = "https://${cloudfoundry_route.server.hostname}.${data.cloudfoundry_domain.public.name}"
}

output "shared_secret" {
  description = "The shared secret for verifying tenant keys"
  value       = random_password.signing_key.result
  sensitive   = true
}

output "client_connection_string" {
  description = "The connection string to use in the client configuration"
  value       = "${cloudfoundry_route.server.hostname}.${data.cloudfoundry_domain.public.name}:4443"
}

output "instance_name" {
  description = "The unique instance name for this deployment"
  value       = random_pet.instance.id
}