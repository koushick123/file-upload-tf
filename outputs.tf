output "ec2_private_key" {
  value     = tls_private_key.file-upload-private-key.private_key_pem
  sensitive = true
}

output "ec2_public_ip" {
  value = aws_instance.file-upload-instance.public_ip
}