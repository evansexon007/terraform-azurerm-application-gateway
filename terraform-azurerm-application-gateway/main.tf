resource "azurerm_application_gateway" "application_gateway" {
  name                = var.app_gateway_name
  resource_group_name = var.resource_group_name
  location            = var.location
  zones               = var.zones

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.appgw_identity.id]
  }

  sku {
    name     = var.sku_name
    tier     = var.sku_tier
    capacity = var.sku_capacity
  }

  gateway_ip_configuration {
    name      = var.gtw_ip_config_name
    subnet_id = var.gtw_ip_config_subnetid
  }

  dynamic "frontend_port" {
    for_each = var.frontend_ports
    content {
      name = frontend_port.value.name
      port = frontend_port.value.port
    }
  }

  dynamic "frontend_ip_configuration" {
    for_each = var.frontend_ip_configs
    content {
      name                          = frontend_ip_configuration.value.name
      public_ip_address_id          = lookup(frontend_ip_configuration.value, "public_ip_address_id", null)
      subnet_id                     = lookup(frontend_ip_configuration.value, "subnet_id", null)
      private_ip_address            = lookup(frontend_ip_configuration.value, "private_ip_address", null)
      private_ip_address_allocation = frontend_ip_configuration.value.private_ip_address != null ? "Static" : "Dynamic"
    }
  }

  dynamic "ssl_profile" {
    for_each = var.ssl_profiles
    content {
      name                             = ssl_profile.value.name
      trusted_client_certificate_names = lookup(ssl_profile.value, "trusted_client_certificate_names", [])
      verify_client_cert_issuer_dn     = lookup(ssl_profile.value, "verify_client_cert_issuer_dn", false)

      ssl_policy {
        disabled_protocols   = lookup(ssl_profile.value.ssl_policy, "disabled_protocols", [])
        policy_type          = lookup(ssl_profile.value.ssl_policy, "policy_type", "Custom")
        policy_name          = lookup(ssl_profile.value.ssl_policy, "policy_name", ssl_profile.value.name)
        cipher_suites        = lookup(ssl_profile.value.ssl_policy, "cipher_suites", [])
        min_protocol_version = lookup(ssl_profile.value.ssl_policy, "min_protocol_version", null)
      }
    }
  }

  dynamic "trusted_client_certificate" {
    for_each = var.trusted_client_certificates
    content {
      name = trusted_client_certificate.value.name
      data = trusted_client_certificate.value.data
    }
  }

  dynamic "trusted_root_certificate" {
    for_each = var.trusted_root_certificates
    content {
      name = trusted_root_certificate.value.name
      data = trusted_root_certificate.value.data
    }
  }


  dynamic "backend_address_pool" {
    for_each = var.backend_address_pools
    content {
      name         = backend_address_pool.value.name
      fqdns        = backend_address_pool.value.fqdns
      ip_addresses = backend_address_pool.value.ip_addresses
    }
  }

  dynamic "backend_http_settings" {
    for_each = var.backend_http_settings
    content {
      name                                = backend_http_settings.value.name
      cookie_based_affinity               = backend_http_settings.value.cookie_based_affinity
      path                                = backend_http_settings.value.path
      port                                = backend_http_settings.value.port
      protocol                            = backend_http_settings.value.protocol
      request_timeout                     = backend_http_settings.value.request_timeout
      pick_host_name_from_backend_address = backend_http_settings.value.pick_host_name_from_backend_address
      trusted_root_certificate_names      = backend_http_settings.value.trusted_root_certificate_names
      probe_name                          = lookup(backend_http_settings.value, "probe_name", null)

      dynamic "authentication_certificate" {
        for_each = backend_http_settings.value.protocol == "Https" && backend_http_settings.value.authentication_certificate_name != null ? [1] : []
        content {
          name = backend_http_settings.value.authentication_certificate_name
        }
      }
    }
  }

  dynamic "http_listener" {
    for_each = var.http_listeners
    content {
      name                           = http_listener.value.name
      frontend_ip_configuration_name = http_listener.value.frontend_ip_configuration_name
      frontend_port_name             = http_listener.value.frontend_port_name
      protocol                       = http_listener.value.protocol
      ssl_certificate_name           = lookup(http_listener.value, "ssl_certificate_name", null)
      host_name                      = lookup(http_listener.value, "host_name", null) # Optional host name
    }
  }

  dynamic "request_routing_rule" {
    for_each = var.request_routing_rules
    content {
      name               = request_routing_rule.value.name
      rule_type          = request_routing_rule.value.rule_type
      http_listener_name = request_routing_rule.value.http_listener_name
      priority           = lookup(request_routing_rule.value, "priority", null)

      backend_address_pool_name   = lookup(request_routing_rule.value, "backend_address_pool_name", null)
      backend_http_settings_name  = lookup(request_routing_rule.value, "backend_http_settings_name", null)
      redirect_configuration_name = lookup(request_routing_rule.value, "redirect_configuration_name", null)
      rewrite_rule_set_name       = lookup(request_routing_rule.value, "rewrite_rule_set_name", null)
    }
  }

  dynamic "redirect_configuration" {
    for_each = var.redirect_configurations
    content {
      name                 = redirect_configuration.value.name
      redirect_type        = redirect_configuration.value.redirect_type
      target_url           = lookup(redirect_configuration.value, "target_url", null)
      target_listener_name = lookup(redirect_configuration.value, "target_listener_name", null)
      include_path         = lookup(redirect_configuration.value, "include_path", false)
      include_query_string = lookup(redirect_configuration.value, "include_query_string", false)
    }
  }

  dynamic "rewrite_rule_set" {
    for_each = var.rewrite_rule_sets
    content {
      name = rewrite_rule_set.value.name

      dynamic "rewrite_rule" {
        for_each = rewrite_rule_set.value.rules
        content {
          name          = rewrite_rule.value.name
          rule_sequence = rewrite_rule.value.rule_sequence

          dynamic "condition" {
            for_each = rewrite_rule.value.conditions
            content {
              variable    = condition.value.variable_name
              pattern     = condition.value.pattern
              negate      = condition.value.negate
              ignore_case = condition.value.ignore_case
            }
          }

          dynamic "request_header_configuration" {
            for_each = rewrite_rule.value.request_headers
            content {
              header_name  = request_header_configuration.value.header_name
              header_value = request_header_configuration.value.header_value
            }
          }

          dynamic "response_header_configuration" {
            for_each = rewrite_rule.value.response_headers
            content {
              header_name  = response_header_configuration.value.header_name
              header_value = response_header_configuration.value.header_value
            }
          }

          dynamic "url" {
            for_each = rewrite_rule.value.url != null ? [1] : []
            content {
              path         = rewrite_rule.value.url != null ? rewrite_rule.value.url.path : null
              query_string = rewrite_rule.value.url != null ? rewrite_rule.value.url.query_string : null
              components   = rewrite_rule.value.url != null ? rewrite_rule.value.url.components : null
              reroute      = rewrite_rule.value.url != null ? rewrite_rule.value.url.reroute : null
            }
          }
        }
      }
    }
  }

  dynamic "probe" {
    for_each = var.probes
    content {
      name                = probe.value.name
      protocol            = probe.value.protocol
      host                = lookup(probe.value, "host", null)
      path                = probe.value.path
      interval            = probe.value.interval
      timeout             = probe.value.timeout
      unhealthy_threshold = probe.value.unhealthy_threshold
      port                = probe.value.port

      # Conditional insertion of match configurations
      dynamic "match" {
        for_each = probe.value.body != null || probe.value.status_code != null ? [probe.value] : []
        content {
          # Include body only if it's provided
          body = probe.value.body != null ? probe.value.body : null

          # Include status_code only if it's provided, ensure it's always a list
          status_code = probe.value.status_code != null ? probe.value.status_code : []
        }
      }
    }
  }

  dynamic "ssl_certificate" {
    for_each = var.ssl_certificates
    content {
      name                = ssl_certificate.value.name
      key_vault_secret_id = ssl_certificate.value.key_vault_secret_id
    }
  }

  waf_configuration {
    enabled          = var.waf_enabled
    firewall_mode    = var.waf_firewall_mode
    rule_set_type    = var.waf_rule_set_type
    rule_set_version = var.waf_rule_set_version
  }

  firewall_policy_id = var.waf_policy_id

  tags = var.common_tags

  lifecycle {
    ignore_changes = []
  }
}

resource "azurerm_user_assigned_identity" "appgw_identity" {
  name                = "${var.app_gateway_name}-identity"
  resource_group_name = var.resource_group_name
  location            = var.location
}

resource "azurerm_monitor_diagnostic_setting" "appgw_diag" {
  count                      = var.log_analytics_workspace_id != null ? 1 : 0
  name                       = "${var.app_gateway_name}-diag"
  target_resource_id         = azurerm_application_gateway.application_gateway.id
  log_analytics_workspace_id = var.log_analytics_workspace_id

  metric {
    category = "AllMetrics"
    enabled  = true
  }
  enabled_log {
    category_group = "allLogs"
  }
}