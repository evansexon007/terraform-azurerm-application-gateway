output "application_gateway_id" {
  description = "The ID of the Application Gateway."
  value       = azurerm_application_gateway.application_gateway.id
}

output "appgw_identity_id" {
  value = azurerm_user_assigned_identity.appgw_identity.id
}

output "appgw_identity_principal_id" {
  value = azurerm_user_assigned_identity.appgw_identity.principal_id
}