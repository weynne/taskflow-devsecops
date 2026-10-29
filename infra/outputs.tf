output "bucket_relatorios" {
  description = "Nome do bucket privado de relatorios"
  value       = aws_s3_bucket.relatorios.bucket
}

output "bucket_logs" {
  description = "Nome do bucket de logs de acesso"
  value       = aws_s3_bucket.logs.bucket
}

output "security_group_id" {
  description = "ID do security group da aplicacao"
  value       = aws_security_group.app.id
}
