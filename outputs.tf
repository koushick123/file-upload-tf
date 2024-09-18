output "rds-endpoint" {
  value = aws_db_instance.file-upload-rds.endpoint
}

output "s3-bucket" {
  value = aws_s3_bucket.media-bucket-2024.bucket
}

output "dynamo-db-name" {
    value = aws_dynamodb_table.upload-table.name
}