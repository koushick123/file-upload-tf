output "ec2_private_key" {
  value     = tls_private_key.file-upload-private-key.private_key_pem
  sensitive = true
}

output "aws-lb-dns-name" {
  value = aws_lb.file-upload-application-LB.dns_name
}

output "ec2_public_ip" {
  value = aws_instance.file-upload-admin-instance.public_ip
}

# output "ec2_user_data" {
#   value = base64decode(data.aws_instance.ec2_instance.user_data_base64)
# }