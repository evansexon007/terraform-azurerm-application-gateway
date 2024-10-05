## Creates an Application Gateway
module "p_agw" {
  source                 = "../../../common/modules/terraform-azurerm-application-gateway"
  app_gateway_name       = "apgw-online-p-uks-01"
  resource_group_name    = module.resource_group_apgw.resource_group_name
  location               = local.location
  zones                  = ["1", "2", "3"]
  sku_name               = "WAF_v2"
  sku_tier               = "WAF_v2"
  sku_capacity           = 2
  waf_enabled            = true
  waf_policy_id          = module.p_waf_policy.waf_policy_id
  gtw_ip_config_name     = "apgw-online-p-gateway-ip-configuration"
  gtw_ip_config_subnetid = module.appgw_spoke_subnets.subnets[local.apgw_subnet_name]

  ## Define Frontend Ports
  frontend_ports = [
    {
      name = "apgw-online-p-frontend-port-443"
      port = 443
    },
    {
      name = "apgw-online-p-frontend-port-80"
      port = 80
    },
    {
      name = "apgw-online-p-frontend-port-7780"
      port = 7780
    },
    {
      name = "apgw-online-p-frontend-port-7777"
      port = 7777
    },
    {
      name = "apgw-online-p-frontend-port-7003"
      port = 7003
    }
  ]

  ## Define Frontend_IP_configurations
  frontend_ip_configs = [
    {
      name                 = "apgw-online-p-frontend-ip-configuration-pub"
      public_ip_address_id = module.frontend_ip_agw.Public_ip_id
      subnet_id            = null
      private_ip_address   = null
    },
    {
      name                 = "apgw-online-p-frontend-ip-configuration-priv"
      public_ip_address_id = null
      subnet_id            = module.appgw_spoke_subnets.subnets[local.apgw_subnet_name]
      private_ip_address   = "10.2.80.200"
    }
  ]

  ## Define Backend Pools
  backend_address_pools = [
    {
      name         = "App3-APP-Backend"
      fqdns        = []
      ip_addresses = ["10.2.24.24"]
    },
    {
      name         = "App1-App-Backend"
      fqdns        = []
      ip_addresses = ["10.2.5.38", "10.2.7.34"]
    },
    {
      name         = "App2-App-Backend"
      fqdns        = []
      ip_addresses = ["10.2.5.46", "10.2.7.40"]
    },

  ]

  ## Define Backend http settings
  backend_http_settings = [
    {
      name                           = "App3-APP-HTTPS-Settings"
      cookie_based_affinity          = "Disabled"
      path                           = "/"
      port                           = 443
      protocol                       = "Https"
      request_timeout                = 20
      probe_name                     = "App3-Probe"
      trusted_root_certificate_names = ["examplerootca"]
    },
    {
      name                           = "App1-APP-HTTP-Settings_7780"
      cookie_based_affinity          = "Enabled"
      path                           = "/"
      port                           = 7780
      protocol                       = "Http"
      request_timeout                = 20
      probe_name                     = "App1-Probe_7780"
      trusted_root_certificate_names = []
    },
    {
      name                           = "App1-APP-HTTP-Settings_7777"
      cookie_based_affinity          = "Enabled"
      path                           = "/"
      port                           = 7777
      protocol                       = "Http"
      request_timeout                = 20
      probe_name                     = "App1-Probe_7777"
      trusted_root_certificate_names = []
    },
    {
      name                           = "App2-APP-HTTP-Settings_7003"
      cookie_based_affinity          = "Enabled"
      path                           = "/"
      port                           = 7003
      protocol                       = "Http"
      request_timeout                = 20
      probe_name                     = "App2-Probe_7003"
      trusted_root_certificate_names = []
    }
  ]

  ## Define http Listeners
  http_listeners = [
    {
      name                           = "App3-APP-HTTPS-Listener-priv"
      frontend_ip_configuration_name = "apgw-online-p-frontend-ip-configuration-priv"
      frontend_port_name             = "apgw-online-p-frontend-port-443"
      protocol                       = "Https"
      ssl_certificate_name           = "apgw-online-p-cert"
      host_name                      = "sourcing.example.co.uk"
    },
    {
      name                           = "App3-APP-HTTPS-Listener-pub"
      frontend_ip_configuration_name = "apgw-online-p-frontend-ip-configuration-pub"
      frontend_port_name             = "apgw-online-p-frontend-port-443"
      protocol                       = "Https"
      ssl_certificate_name           = "apgw-online-p-cert"
      host_name                      = "sourcing.example.co.uk"
    },
    {
      name                           = "App1-APP-HTTP-Listener-priv"
      frontend_ip_configuration_name = "apgw-online-p-frontend-ip-configuration-priv"
      frontend_port_name             = "apgw-online-p-frontend-port-7780"
      protocol                       = "Http"
      ssl_certificate_name           = ""
      host_name                      = "App1"
    },
    {
      name                           = "App1-APP-HTTP-Listener-priv_example"
      frontend_ip_configuration_name = "apgw-online-p-frontend-ip-configuration-priv"
      frontend_port_name             = "apgw-online-p-frontend-port-7780"
      protocol                       = "Http"
      ssl_certificate_name           = ""
      host_name                      = "App1.example.local"
    },
    {
      name                           = "App1-APP-HTTP-Listener-priv_7777"
      frontend_ip_configuration_name = "apgw-online-p-frontend-ip-configuration-priv"
      frontend_port_name             = "apgw-online-p-frontend-port-7777"
      protocol                       = "Http"
      ssl_certificate_name           = ""
      host_name                      = "App1"
    },
    {
      name                           = "App2-APP-HTTP-Listener-priv"
      frontend_ip_configuration_name = "apgw-online-p-frontend-ip-configuration-priv"
      frontend_port_name             = "apgw-online-p-frontend-port-7003"
      protocol                       = "Http"
      ssl_certificate_name           = ""
      host_name                      = "App2.example.local"
    }
  ]

  ## Define Routing Rules
  request_routing_rules = [
    {
      name                       = "App3-APP-HTTPS-Rule-pub"
      rule_type                  = "Basic"
      http_listener_name         = "App3-APP-HTTPS-Listener-pub"
      backend_address_pool_name  = "App3-APP-Backend"
      backend_http_settings_name = "App3-APP-HTTPS-Settings"
      priority                   = 100
    },
    {
      name                       = "App3-APP-HTTPS-Rule-priv"
      rule_type                  = "Basic"
      http_listener_name         = "App3-APP-HTTPS-Listener-priv"
      backend_address_pool_name  = "App3-APP-Backend"
      backend_http_settings_name = "App3-APP-HTTPS-Settings"
      priority                   = 200
    },
    {
      name                       = "App1_Routing_rule"
      rule_type                  = "Basic"
      http_listener_name         = "App1-APP-HTTP-Listener-priv"
      backend_address_pool_name  = "App1-App-Backend"
      backend_http_settings_name = "App1-APP-HTTP-Settings_7780"
      priority                   = 250
    },
    {
      name                       = "App2_Routing_rule"
      rule_type                  = "Basic"
      http_listener_name         = "App2-APP-HTTP-Listener-priv"
      backend_address_pool_name  = "App2-App-Backend"
      backend_http_settings_name = "App2-APP-HTTP-Settings_7003"
      rewrite_rule_set_name      = "RewriteApp2InternalHosts"
      priority                   = 300
    },
    {
      name                       = "App1_Routing_rule_7777"
      rule_type                  = "Basic"
      http_listener_name         = "App1-APP-HTTP-Listener-priv_7777"
      backend_address_pool_name  = "App1-App-Backend"
      backend_http_settings_name = "App1-APP-HTTP-Settings_7777"
      priority                   = 350
    },
    {
      name                       = "App1_Routing_rule_example"
      rule_type                  = "Basic"
      http_listener_name         = "App1-APP-HTTP-Listener-priv_example"
      backend_address_pool_name  = "App1-App-Backend"
      backend_http_settings_name = "App1-APP-HTTP-Settings_7780"
      priority                   = 400
    }
  ]

  ## Define Health Probes
  probes = [
    {
      name                = "App3-Probe"
      protocol            = "Https"
      host                = "sourcing.example.co.uk"
      path                = "/startPage"
      interval            = 30
      timeout             = 30
      unhealthy_threshold = 3
      status_code         = ["200-399"]
    },
    {
      name                = "App1-Probe_7780"
      protocol            = "Http"
      host                = "App1"
      path                = "/"
      interval            = 30
      timeout             = 30
      unhealthy_threshold = 3
      status_code         = ["200-470"]
      port                = "7780"
    },
    {
      name                = "App1-Probe_7777"
      protocol            = "Http"
      host                = "App1"
      path                = "/"
      interval            = 30
      timeout             = 30
      unhealthy_threshold = 3
      status_code         = ["200-470"]
      port                = "7777"
    },
    {
      name                = "App2-Probe_7003"
      protocol            = "Http"
      host                = "App2.example.local"
      path                = "/"
      interval            = 30
      timeout             = 30
      unhealthy_threshold = 3
      status_code         = ["200-470"]
      port                = "7003"
    }
  ]

  ## Rewrite rule sets

  # Rewrite rule set for App1 SSO

  rewrite_rule_sets = [
    {
      name = "RewriteApp1InternalHostsSSO"
      rules = [
        {
          name          = "RewriteInternalHostProdSSO"
          rule_sequence = 80
          conditions = [
            {
              variable_name = "http_resp_Location"
              # Only match the backend URLs and exclude already rewritten URLs
              pattern     = "(http?):\\/\\/exampledprodap31(dr)?\\.example\\.local(.*)$"
              negate      = false
              ignore_case = true
            },
            {
              variable_name = "http_req_Host"
              # Make sure the rewrite is not applied to the already rewritten URL (App1)
              pattern     = "App1:7780"
              negate      = true # Exclude App1:7780 from being rewritten again
              ignore_case = true
            }
          ]
          response_headers = [
            {
              header_name = "Location"
              # Rewrite the backend server URL to the public load balancer URL
              header_value = "http://App1:7780/forms/frmservlet?config=prod_sso"
            }
          ]
        },
        {
          name          = "RewriteBackendURLInResponse"
          rule_sequence = 90
          conditions = [
            {
              variable_name = "http_resp_Location"
              # Catch backend URL with different port
              pattern     = "(http?):\\/\\/exampledprodap31\\.example\\.local:24100(.*)$"
              negate      = false
              ignore_case = true
            }
          ]
          response_headers = [
            {
              header_name = "Location"
              # Rewrite to the load balancer URL to mask the backend server URL
              header_value = "http://App1:7780/forms/frmservlet?config=prod_sso"
            }
          ]
        }
      ]
    },

    # Rewrite rule set for App1 Prod
    {
      name = "RewriteApp1InternalHostsProd"
      rules = [
        {
          name          = "RewriteInternalHostProd"
          rule_sequence = 95
          conditions = [
            {
              variable_name = "http_resp_Location"
              # Matches both 'exampledprodap31' and 'exampledprodap31dr'
              pattern     = "(http?):\\/\\/exampledprodap31(dr)?\\.example\\.local(.*)$"
              negate      = false
              ignore_case = true
            }
          ]
          response_headers = [
            {
              header_name  = "Location"
              header_value = "http://App1:7777/forms/frmservlet?config=prod"
            }
          ]
        }
      ]
    },

    # Rewrite rule set for App2
    {
      name = "RewriteApp2InternalHosts"
      rules = [
        {
          name          = "RewriteInternalHostApp2"
          rule_sequence = 100
          conditions = [
            {
              variable_name = "http_resp_Location"
              # Matches both 'examplemvsprap31' and 'examplemvsdrap32'
              pattern     = "(http?):\\/\\/examplemvsprap31|examplemvsdrap32\\.example\\.local(.*)$"
              negate      = false
              ignore_case = true
            }
          ]
          response_headers = [
            {
              header_name  = "Location"
              header_value = "http://App2.example.local:7003/App2/index"
            }
          ]
        }
      ]
    }
  ]


  ## Define SSL Profiles
  ssl_profiles = [
    {
      name                             = "apgw-ssl-profile"
      trusted_client_certificate_names = []
      verify_client_cert_issuer_dn     = false
      ssl_policy = {
        policy_type          = "Custom"
        cipher_suites        = ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"]
        min_protocol_version = "TLSv1_2"
        disabled_protocols   = []
      }
    }
  ]

  ssl_certificates = [
    {
      name                = "apgw-online-p-cert"
      key_vault_secret_id = data.azurerm_key_vault_certificate.examplewildcard.secret_id
    }
  ]

  ## caroot

  trusted_root_certificates = [
    {
      name = "examplerootca"
      data = data.azurerm_key_vault_secret.examplerootca.value
    }
  ]

  log_analytics_workspace_id = data.azurerm_log_analytics_workspace.log_analytics_workspace.id
  common_tags                = module.tags.tags_appgwonlinep
}

## Output Appgw User Identity which gets created by the module
output "appgw_identity_id" {
  value = module.p_agw.appgw_identity_id
}

output "appgw_identity_principal_id" {
  value = module.p_agw.appgw_identity_principal_id
}

## Define AppGW Public IP
module "frontend_ip_agw" {
  source            = "../../../common/modules/terraform-azurerm-public-ip"
  location          = local.location
  region            = local.region
  platform_name     = local.apgw_platform_name
  purpose           = "agw-p"
  resource_type     = "pip"
  resource_suffix   = "001"
  rg_name           = module.resource_group_apgw.resource_group_name
  pip_type          = "Static"
  pip_sku           = "Standard"
  domain_name_label = ""
  zones             = ["1", "2", "3"]
}

## Define Web Application Firewall Policy
# Root module

module "p_waf_policy" {
  source              = "../../../common/modules/terraform-azurerm_web_application_firewall_policy"
  resource_group_name = module.resource_group_apgw.resource_group_name
  location            = local.location
  waf_policy_name     = "apgw-online-p-wafpolicy"
  common_tags         = local.common_tags

  policy_settings = {
    enabled                     = true
    mode                        = "Prevention"
    request_body_check          = true
    file_upload_limit_in_mb     = 100
    max_request_body_size_in_kb = 128
  }

  managed_rules = {
    exclusions = []
    rule_sets = [
      {
        type    = "OWASP"
        version = "3.2"
        rule_group_overrides = [
          {
            rule_group_name = "REQUEST-942-APPLICATION-ATTACK-SQLI"
            rules = [
              {
                id      = "942130"
                enabled = true
                action  = "Log"
              },
              {
                id      = "942430"
                enabled = true
                action  = "Log"
              },
              {
                id      = "942120"
                enabled = true
                action  = "Log"
              },
              {
                id      = "942340"
                enabled = true
                action  = "Log"
              }
            ]
          }
        ]
      }
    ]
  }

  custom_rules = [
    # Rule 1: Allow internal IP addresses (No need for GeoMatch)
    {
      name      = "AllowInternalIPs"
      priority  = 1
      rule_type = "MatchRule"
      match_conditions = [
        {
          match_variables = [
            {
              variable_name = "RemoteAddr"
              selector      = null
            }
          ]
          operator           = "IPMatch"
          negation_condition = false                                             # Allow matching internal IPs
          match_values       = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"] # Internal IP ranges
        }
      ]
      action = "Allow" # Allow internal IPs
    },

    # Rule 2: Block external traffic not from allowed countries
    {
      name      = "BlockNonAllowedCountries"
      priority  = 2
      rule_type = "MatchRule"
      match_conditions = [
        {
          match_variables = [
            {
              variable_name = "RemoteAddr"
              selector      = null
            }
          ]
          operator           = "GeoMatch"
          negation_condition = true                                                                                                                                                                                                   # Negate to allow only specific countries
          match_values       = ["GB", "IN", "FR", "DE", "ES", "IT", "NL", "BE", "CH", "AT", "SE", "NO", "DK", "FI", "IE", "PT", "GR", "PL", "CZ", "HU", "RO", "BG", "HR", "SI", "SK", "LT", "LV", "EE", "CY", "MT", "LU", "IS", "LI"] # Allowed countries
        }
      ]
      action = "Block" # Block everything else
    }
  ]
}

data "azurerm_key_vault_certificate" "examplewildcard" {
  name         = "examplewildcard"
  key_vault_id = module.keyvault_shared.id
}

data "azurerm_key_vault_secret" "examplerootca" {
  name         = "examplerootca"
  key_vault_id = module.keyvault_shared.id
}
