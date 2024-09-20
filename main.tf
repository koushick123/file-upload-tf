# Create a VPC
resource "aws_vpc" "file-upload-vpc" {
  cidr_block = "10.100.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support = true
}

resource "aws_default_security_group" "default-sg-rds" {
  vpc_id = data.aws_vpc.file-upload-vpc.id
}

resource "aws_vpc_security_group_ingress_rule" "default-sg-rds-ingress" {
  security_group_id = aws_default_security_group.default-sg-rds.id
  ip_protocol = "tcp"
  from_port = 3306
  to_port = 3306
  cidr_ipv4 = "0.0.0.0/0"
}

resource "aws_vpc_security_group_egress_rule" "default-sg-rds-egress" {
  security_group_id = aws_default_security_group.default-sg-rds.id
  ip_protocol = "All"
  from_port = -1
  to_port = -1
  cidr_ipv4 = "0.0.0.0/0"
}

resource "aws_default_route_table" "file-upload-route-table" {
  default_route_table_id  = aws_vpc.file-upload-vpc.default_route_table_id

  route {
    cidr_block = aws_vpc.file-upload-vpc.cidr_block
    gateway_id = "local"
  }

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.file-upload-igw.id
  }
}

# Create a subnet within the VPC
resource "aws_subnet" "file-upload-subnet-az-1a" {
  vpc_id     = aws_vpc.file-upload-vpc.id
  cidr_block = "10.100.1.0/24"
  availability_zone = "ap-south-1a"
}

resource "aws_internet_gateway" "file-upload-igw" {
  vpc_id = aws_vpc.file-upload-vpc.id
}

resource "aws_subnet" "file-upload-subnet-az-1b" {
  vpc_id     = aws_vpc.file-upload-vpc.id
  cidr_block = "10.100.2.0/24"
  availability_zone = "ap-south-1b"
}

resource "aws_db_subnet_group" "db_subnets" {
  name       = "upload-subnet-group"
  subnet_ids = [aws_subnet.file-upload-subnet-az-1a.id, aws_subnet.file-upload-subnet-az-1b.id]

  tags = {
    Name = "My DB subnet group"
  }
}

# Create a security group for the RDS instance
# resource "aws_security_group" "file-upload-sg" {
#   name        = "rds-sg"
#   description = "Security group for RDS"
#   vpc_id      = aws_vpc.file-upload-vpc.id
# }

# Create an RDS instance
resource "aws_db_instance" "file-upload-rds" {
  identifier = "file-upload"
  engine                = "mysql"
  engine_version        = "8.0.32"
  allocated_storage     = 20
  storage_type          = "gp3"
  instance_class        = "db.c6gd.medium"
  username              = "admin"
  password              = "rdspassword"
  availability_zone     = "ap-south-1a"
  db_name = "upload"
  publicly_accessible = true
  skip_final_snapshot = true
  vpc_security_group_ids = [aws_default_security_group.default-sg-rds.id]
  db_subnet_group_name = aws_db_subnet_group.db_subnets.name  
}

# Create an S3 bucket
resource "aws_s3_bucket" "media-bucket-2024" {
  bucket = "media-bucket-2024"
}


# Disable Block Public Access Settings
resource "aws_s3_bucket_public_access_block" "my_bucket_public_access_block" {
  bucket = aws_s3_bucket.media-bucket-2024.id

  block_public_acls       = false  # Disable BlockPublicAcls
  ignore_public_acls       = false  # Allow ACLs
  block_public_policy      = false  # Disable BlockPublicPolicy
  restrict_public_buckets  = false  # Allow public bucket
}

# Create a DynamoDB table
resource "aws_dynamodb_table" "upload-table" {
  name           = "upload"
  billing_mode = "PAY_PER_REQUEST"
    
  hash_key = "file-id"

  attribute {
    name = "file-id"
    type = "N"
  }
}

# Create AWS Secret Manager for RDS Login
resource "aws_secretsmanager_secret" "rds-login-username-secret" {
  name = "usernamesecret"
  recovery_window_in_days = 0  
}

resource "aws_secretsmanager_secret" "rds-login-password-secret" {
  name = "passwordsecret"
  recovery_window_in_days = 0  
}

resource "aws_secretsmanager_secret" "rds-login-endpint-secret" {
  name = "endpointsecret"
  recovery_window_in_days = 0  
}

# Create AWS Secret values for RDS Login
resource "aws_secretsmanager_secret_version" "rds-login-username" {
  secret_id     = aws_secretsmanager_secret.rds-login-username-secret.id
  secret_string = "admin"
}

resource "aws_secretsmanager_secret_version" "rds-login-password" {
  secret_id     = aws_secretsmanager_secret.rds-login-password-secret.id
  secret_string = "rdspassword"
}

resource "aws_secretsmanager_secret_version" "rds-login-endpoint" {
  secret_id     = aws_secretsmanager_secret.rds-login-endpint-secret.id
  secret_string = "jdbc:mysql://${data.aws_db_instance.file-upload-rds.endpoint}/${data.aws_db_instance.file-upload-rds.db_name}"
}