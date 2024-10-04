output "rds-endpoint" {
  value = aws_db_instance.file-upload-rds.endpoint
}

output "s3-bucket" {
  value = aws_s3_bucket.media-bucket-2024.bucket
}

output "dynamo-db-name" {
    value = aws_dynamodb_table.upload-table.name
}

output "dynamod-db-vpc-endpoint-dns" {
  value = aws_vpc_endpoint.file-upload-endpoint.dns_entry
}

output "ec2_private_key" {
  value = tls_private_key.file-upload-private-key.private_key_pem
  sensitive = true
}