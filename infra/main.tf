# Infraestrutura da TaskFlow na AWS, corrigida a partir do main.insecure.tf do
# laboratorio (Encontro 12). Cada "CORRIGIDO (FALHA N)" usa a numeracao do
# arquivo original. Verificado com terraform validate, Checkov e Trivy config
# no workflow .github/workflows/iac-scan.yml (sem apply: nao ha conta AWS).
#
# Todo "#checkov:skip" / "#trivy:ignore" tem a justificativa na propria linha.

# CORRIGIDO (FALHA 7): nenhuma credencial no codigo. O provider usa a cadeia
# padrao da AWS (variaveis de ambiente, perfil local ou OIDC no CI).
provider "aws" {
  region = var.aws_region

  # CORRIGIDO (FALHA 1): tags de governanca aplicadas a TODOS os recursos.
  default_tags {
    tags = local.tags
  }
}

data "aws_caller_identity" "current" {}

locals {
  name_prefix = "taskflow-${var.environment}"
  tags = {
    Project     = "taskflow"
    Environment = var.environment
    Owner       = var.owner
    ManagedBy   = "terraform"
  }
}

# -----------------------------------------------------------------------------
# Chave KMS gerenciada pelo cliente para os dados da aplicacao
# -----------------------------------------------------------------------------
resource "aws_kms_key" "dados" {
  description             = "Criptografia em repouso dos relatorios da TaskFlow"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AdministracaoPelaConta"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      }
    ]
  })
}

resource "aws_kms_alias" "dados" {
  name          = "alias/${local.name_prefix}-dados"
  target_key_id = aws_kms_key.dados.key_id
}

# -----------------------------------------------------------------------------
# Bucket de relatorios (dados da aplicacao)
# -----------------------------------------------------------------------------
resource "aws_s3_bucket" "relatorios" {
  #checkov:skip=CKV_AWS_144:Replicacao entre regioes fora do escopo do laboratorio (custo e segunda regiao); a recuperacao vem do versionamento + KMS.
  #checkov:skip=CKV2_AWS_62:Nao ha consumidor de eventos do bucket (fila/lambda); notificacao sem destino nao agrega controle.
  bucket = "${local.name_prefix}-relatorios-${data.aws_caller_identity.current.account_id}"
}

# CORRIGIDO (FALHA 2): bucket privado. Bloqueio de acesso publico com os
# quatro campos ligados e ACLs desativadas (o dono do bucket e dono de tudo).
resource "aws_s3_bucket_public_access_block" "relatorios" {
  bucket                  = aws_s3_bucket.relatorios.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "relatorios" {
  bucket = aws_s3_bucket.relatorios.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# CORRIGIDO (FALHA 3): criptografia em repouso com chave KMS do cliente.
resource "aws_s3_bucket_server_side_encryption_configuration" "relatorios" {
  bucket = aws_s3_bucket.relatorios.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.dados.arn
    }
    bucket_key_enabled = true
  }
}

# CORRIGIDO (FALHA 4): versionamento contra sobrescrita/exclusao acidental.
resource "aws_s3_bucket_versioning" "relatorios" {
  bucket = aws_s3_bucket.relatorios.id
  versioning_configuration {
    status = "Enabled"
  }
}

# CORRIGIDO (FALHA 5): log de acesso para investigacao de incidentes.
resource "aws_s3_bucket_logging" "relatorios" {
  bucket        = aws_s3_bucket.relatorios.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "s3-access/relatorios/"
}

resource "aws_s3_bucket_lifecycle_configuration" "relatorios" {
  bucket = aws_s3_bucket.relatorios.id
  rule {
    id     = "versoes-antigas"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration {
      noncurrent_days = 90
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# Recusa qualquer acesso sem TLS.
resource "aws_s3_bucket_policy" "relatorios" {
  bucket     = aws_s3_bucket.relatorios.id
  depends_on = [aws_s3_bucket_public_access_block.relatorios]
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "SomenteTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.relatorios.arn, "${aws_s3_bucket.relatorios.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      }
    ]
  })
}

# -----------------------------------------------------------------------------
# Bucket de logs de acesso (destino do aws_s3_bucket_logging acima)
# -----------------------------------------------------------------------------
#trivy:ignore:AWS-0089 Este E o bucket de destino dos logs de acesso; logar o bucket de logs nele mesmo cria um laco de escrita.
resource "aws_s3_bucket" "logs" {
  #checkov:skip=CKV_AWS_18:Este E o bucket de destino dos logs de acesso; logar o bucket de logs nele mesmo cria um laco de escrita.
  #checkov:skip=CKV_AWS_144:Replicacao entre regioes fora do escopo do laboratorio (custo e segunda regiao).
  #checkov:skip=CKV2_AWS_62:Bucket de logs nao tem consumidor de eventos.
  #checkov:skip=CKV_AWS_145:A entrega de server access logs do S3 so suporta SSE-S3 (AES256) no bucket de destino, nao SSE-KMS (documentacao AWS).
  bucket = "${local.name_prefix}-logs-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

#trivy:ignore:AWS-0132 A entrega de server access logs do S3 so suporta SSE-S3 (AES256) no bucket de destino, nao SSE-KMS.
resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    id     = "retencao-de-logs"
    status = "Enabled"
    filter {}
    expiration {
      days = var.log_retention_days
    }
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# Com BucketOwnerEnforced, a entrega de logs e autorizada por policy (e nao
# por ACL): so o servico de logging do S3, so a partir do bucket de origem e
# da propria conta, e so via TLS.
resource "aws_s3_bucket_policy" "logs" {
  bucket     = aws_s3_bucket.logs.id
  depends_on = [aws_s3_bucket_public_access_block.logs]
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EntregaDeLogsDoS3"
        Effect    = "Allow"
        Principal = { Service = "logging.s3.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.logs.arn}/s3-access/*"
        Condition = {
          ArnLike      = { "aws:SourceArn" = aws_s3_bucket.relatorios.arn }
          StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
        }
      },
      {
        Sid       = "SomenteTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.logs.arn, "${aws_s3_bucket.logs.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      }
    ]
  })
}

# -----------------------------------------------------------------------------
# Security group da aplicacao
# -----------------------------------------------------------------------------
# CORRIGIDO (FALHA 6): entrada so na porta HTTPS e so a partir do CIDR da
# variavel validada; SSH e Postgres nao sao mais expostos. Saida restrita ao
# banco dentro da VPC (antes: tudo para 0.0.0.0/0).
resource "aws_security_group" "app" {
  #checkov:skip=CKV2_AWS_5:O SG e anexado ao balanceador/instancia no modulo de compute, fora do escopo deste laboratorio (so S3 + rede).
  name        = "${local.name_prefix}-app"
  description = "TaskFlow: HTTPS a partir do CIDR autorizado; saida so para o banco na VPC"
  vpc_id      = var.vpc_id

  ingress {
    description = "HTTPS a partir do CIDR autorizado (var.allowed_ingress_cidr)"
    from_port   = var.app_port
    to_port     = var.app_port
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ingress_cidr]
  }

  egress {
    description = "Aplicacao -> PostgreSQL dentro da VPC"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }
}
