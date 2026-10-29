variable "aws_region" {
  description = "Regiao AWS onde os recursos serao criados"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Ambiente (dev, hml, prod): entra no nome e nas tags dos recursos"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "hml", "prod"], var.environment)
    error_message = "environment deve ser dev, hml ou prod."
  }
}

variable "owner" {
  description = "Time responsavel pelos recursos (tag de governanca)"
  type        = string
  default     = "grupo-wjd"
}

variable "vpc_id" {
  description = "VPC onde o security group da aplicacao e criado"
  type        = string
  default     = "vpc-00000000000000000"
}

variable "vpc_cidr" {
  description = "Faixa da VPC: destino unico permitido na saida da aplicacao (banco)"
  type        = string
  default     = "10.0.0.0/16"

  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "vpc_cidr deve ser um CIDR valido."
  }
}

# CORRIGIDO (FALHA 6): a origem permitida e uma variavel, nunca 0.0.0.0/0.
# A validacao impede que alguem reabra o security group para a internet
# inteira via tfvars sem passar por revisao de codigo.
variable "allowed_ingress_cidr" {
  description = "Unico CIDR autorizado a acessar a aplicacao (ex.: IP da VPN corporativa)"
  type        = string
  default     = "203.0.113.10/32"

  validation {
    condition     = can(cidrhost(var.allowed_ingress_cidr, 0)) && !startswith(var.allowed_ingress_cidr, "0.0.0.0/")
    error_message = "allowed_ingress_cidr deve ser um CIDR valido e diferente de 0.0.0.0/0."
  }
}

variable "app_port" {
  description = "Porta HTTPS exposta pelo balanceador da aplicacao"
  type        = number
  default     = 443
}

variable "log_retention_days" {
  description = "Dias de retencao dos logs de acesso ao bucket"
  type        = number
  default     = 365
}
