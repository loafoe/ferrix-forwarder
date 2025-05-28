# terraform-ferrix-cf-server

Terraform module to deploy the server component of ferrix-forwarder

## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_cloudfoundry"></a> [cloudfoundry](#requirement\_cloudfoundry) | 0.53.1 |
| <a name="requirement_hsdp"></a> [hsdp](#requirement\_hsdp) | 0.67.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_cloudfoundry"></a> [cloudfoundry](#provider\_cloudfoundry) | 0.53.1 |
| <a name="provider_hsdp"></a> [hsdp](#provider\_hsdp) | 0.67.0 |
| <a name="provider_random"></a> [random](#provider\_random) | 3.7.2 |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [cloudfoundry_app.server](https://registry.terraform.io/providers/cloudfoundry-community/cloudfoundry/0.53.1/docs/resources/app) | resource |
| [cloudfoundry_route.server](https://registry.terraform.io/providers/cloudfoundry-community/cloudfoundry/0.53.1/docs/resources/route) | resource |
| [hsdp_tenant_key.key](https://registry.terraform.io/providers/philips-software/hsdp/0.67.0/docs/resources/tenant_key) | resource |
| [random_password.salt](https://registry.terraform.io/providers/hashicorp/random/latest/docs/resources/password) | resource |
| [random_password.signing_key](https://registry.terraform.io/providers/hashicorp/random/latest/docs/resources/password) | resource |
| [random_pet.instance](https://registry.terraform.io/providers/hashicorp/random/latest/docs/resources/pet) | resource |
| [cloudfoundry_domain.internal](https://registry.terraform.io/providers/cloudfoundry-community/cloudfoundry/0.53.1/docs/data-sources/domain) | data source |
| [cloudfoundry_domain.public](https://registry.terraform.io/providers/cloudfoundry-community/cloudfoundry/0.53.1/docs/data-sources/domain) | data source |
| [cloudfoundry_org.org](https://registry.terraform.io/providers/cloudfoundry-community/cloudfoundry/0.53.1/docs/data-sources/org) | data source |
| [cloudfoundry_space.space](https://registry.terraform.io/providers/cloudfoundry-community/cloudfoundry/0.53.1/docs/data-sources/space) | data source |
| [hsdp_config.cf](https://registry.terraform.io/providers/philips-software/hsdp/0.67.0/docs/data-sources/config) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_cf_org_name"></a> [cf\_org\_name](#input\_cf\_org\_name) | n/a | `string` | n/a | yes |
| <a name="input_cf_password"></a> [cf\_password](#input\_cf\_password) | n/a | `string` | n/a | yes |
| <a name="input_cf_space_name"></a> [cf\_space\_name](#input\_cf\_space\_name) | n/a | `string` | `"test"` | no |
| <a name="input_cf_user"></a> [cf\_user](#input\_cf\_user) | n/a | `string` | n/a | yes |
| <a name="input_ferrix_forwarder_client_image"></a> [ferrix\_forwarder\_client\_image](#input\_ferrix\_forwarder\_client\_image) | n/a | `string` | `"ghcr.io/loafoe/ferrix-forwarder-client:v0.3.0"` | no |
| <a name="input_ferrix_forwarder_server_image"></a> [ferrix\_forwarder\_server\_image](#input\_ferrix\_forwarder\_server\_image) | n/a | `string` | `"ghcr.io/loafoe/ferrix-forwarder-server:v0.3.0"` | no |
| <a name="input_region"></a> [region](#input\_region) | n/a | `string` | `"us-east"` | no |
| <a name="input_server_instances"></a> [server\_instances](#input\_server\_instances) | n/a | `number` | `2` | no |
| <a name="input_signing_key"></a> [signing\_key](#input\_signing\_key) | n/a | `string` | `""` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_client_connection_string"></a> [client\_connection\_string](#output\_client\_connection\_string) | The connection string to use in the client configuration |
| <a name="output_instance_name"></a> [instance\_name](#output\_instance\_name) | The unique instance name for this deployment |
| <a name="output_server_domain"></a> [server\_domain](#output\_server\_domain) | The domain of the deployed ferrix-forwarder server |
| <a name="output_server_hostname"></a> [server\_hostname](#output\_server\_hostname) | The hostname of the deployed ferrix-forwarder server |
| <a name="output_server_url"></a> [server\_url](#output\_server\_url) | The full URL of the deployed ferrix-forwarder server |
| <a name="output_shared_secret"></a> [shared\_secret](#output\_shared\_secret) | The shared secret for verifying tenant keys |
