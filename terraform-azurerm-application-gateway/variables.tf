variable "app_gateway_name" {
  description = "Application gateway name"
  type        = string
}

variable "resource_group_name" {
  description = "Resource group name"
  type        = string
}

variable "location" {
  description = "The location/region where the resource group will be created."
  type        = string
}

variable "sku_name" {
  description = "Sku name"
  type        = string
}

variable "frontend_ip_configs" {
  description = "List of frontend IP configurations for the Application Gateway."
  type = list(object({
    name                 = string
    public_ip_address_id = optional(string)
    subnet_id            = optional(string)
    private_ip_address   = optional(string)
  }))
}

variable "sku_tier" {
  description = "Sku tier"
  type        = string
}

variable "sku_capacity" {
  description = "Sku capacity"
  type        = number
}

variable "gtw_ip_config_name" {
  description = "Gateway ip configuration name"
  type        = string
}

variable "gtw_ip_config_subnetid" {
  description = "Gateway ip configuration subnet id"
  type        = string
}

variable "frontend_ports" {
  description = "List of frontend ports for the Application Gateway."
  type = list(object({
    name = string
    port = number
  }))
  default = []
}

variable "private_frontend_ip_address" {
  description = "The private IP address for the frontend configuration"
  type        = string
  default     = null # Use null for dynamic allocation
}

variable "backend_address_pools" {
  description = "List of backend address pools"
  type = list(object({
    name         = string
    fqdns        = optional(list(string), [])
    ip_addresses = optional(list(string), [])
  }))
}

variable "backend_http_settings" {
  description = "List of backend HTTP settings"
  type = list(object({
    name                                = string
    cookie_based_affinity               = string
    path                                = string
    port                                = number
    protocol                            = string
    request_timeout                     = number
    probe_name                          = optional(string)
    authentication_certificate_name     = optional(string, null)
    trusted_root_certificate_names      = optional(list(string), null)
    pick_host_name_from_backend_address = optional(string)
  }))
}

variable "ssl_certificates" {
  description = "List of SSL certificates for the Application Gateway."
  type = list(object({
    name                = string
    key_vault_secret_id = string
  }))
  default = []
}

variable "ssl_profiles" {
  description = "List of SSL profiles for the Application Gateway."
  type = list(object({
    name                             = string
    trusted_client_certificate_names = optional(list(string), [])
    verify_client_cert_issuer_dn     = optional(bool, false)
    ssl_policy = optional(object({
      disabled_protocols   = optional(list(string), [])
      policy_type          = optional(string, "Custom")
      policy_name          = optional(string, "")
      cipher_suites        = optional(list(string), [])
      min_protocol_version = optional(string)
    }), {})
  }))
  default = []
}

variable "trusted_client_certificates" {
  description = "List of trusted client certificates for the Application Gateway."
  type = list(object({
    name      = string
    secret_id = optional(string)
    data      = string
  }))
  default = []
}

variable "http_listeners" {
  description = "List of HTTP listeners"
  type = list(object({
    name                           = string
    frontend_ip_configuration_name = string
    frontend_port_name             = string
    protocol                       = string
    ssl_certificate_name           = optional(string)
    host_name                      = optional(string) # Optional host name
  }))
}

variable "request_routing_rules" {
  description = "List of request routing rules"
  type = list(object({
    name                        = string
    rule_type                   = string
    http_listener_name          = string
    backend_address_pool_name   = optional(string)
    backend_http_settings_name  = optional(string)
    redirect_configuration_name = optional(string)
    priority                    = optional(number)
    rewrite_rule_set_name       = optional(string)
  }))
}

variable "probes" {
  description = "List of probes"
  type = list(object({
    name                = string
    protocol            = string
    host                = optional(string)
    path                = string
    interval            = number
    timeout             = number
    unhealthy_threshold = number
    body                = optional(string) # Optional body content for matching
    status_code         = list(string)     # Required, list of acceptable status codes
    port                = optional(string)
  }))
  default = []
}

variable "common_tags" {
  type    = map(string)
  default = {}
}

variable "log_analytics_workspace_id" {
  description = "Log Analytics Workspace Id"
  type        = string
  default     = null
}

variable "request_routing_rule_priority" {
  description = "The priority of the request routing rule."
  type        = number
  default     = 100 # Adjust the default value as needed
}

variable "https_request_routing_rule_priority" {
  description = "The priority of the HTTPS request routing rule."
  type        = number
  default     = 110 # Adjust the default value as needed
}

variable "waf_enabled" {
  description = "Whether the WAF is enabled or not"
  type        = bool
  default     = false
}

variable "waf_firewall_mode" {
  description = "The firewall mode for the WAF. Possible values are Detection or Prevention"
  type        = string
  default     = "Prevention"
}

variable "waf_rule_set_type" {
  description = "The rule set type for the WAF. For example, OWASP"
  type        = string
  default     = "OWASP"
}

variable "waf_rule_set_version" {
  description = "The rule set version for the WAF. For example, 3.2"
  type        = string
  default     = "3.2"
}

variable "zones" {
  description = "The availability zones for AppGW"
  type        = list(string)
  default     = []
}

variable "waf_policy_id" {
  description = "The ID of the Web Application Firewall Policy."
  type        = string
  default     = null
}

variable "trusted_root_certificates" {
  description = "List of trusted root certificates for the Application Gateway."
  type = list(object({
    name = string
    data = string
  }))
  default = []
}

variable "rewrite_rule_sets" {
  description = "List of rewrite rule sets"
  type = list(object({
    name = string
    rules = list(object({
      name          = string
      rule_sequence = number
      conditions = list(object({
        variable_name = string
        pattern       = string
        negate        = optional(bool, false)
        ignore_case   = optional(bool, false)
      }))
      request_headers = optional(list(object({
        header_name  = string
        header_value = string
      })), [])
      response_headers = optional(list(object({
        header_name  = string
        header_value = string
      })), [])
      url = optional(object({
        path         = optional(string, null)
        query_string = optional(string, null)
        components   = optional(string, null)
        reroute      = optional(bool, false)
      }), null)
    }))
  }))
  default = []
}

variable "redirect_configurations" {
  description = "List of redirect configurations for application gateway"
  type = list(object({
    name                 = string
    redirect_type        = string
    target_listener_name = optional(string)
    target_url           = optional(string)
    include_path         = optional(bool, true)
    include_query_string = optional(bool, true)
  }))
  default = []
}
