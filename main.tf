# Create a VPC
resource "aws_vpc" "file-upload-vpc" {
  cidr_block = "10.100.0.0/16"
  default_security_group_id = null
}

# Create a subnet within the VPC
resource "aws_subnet" "file-upload-subnet-az-1a" {
  vpc_id     = aws_vpc.file-upload-vpc.id
  cidr_block = "10.100.1.0/24"
  availability_zone = "ap-south-1a"
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
resource "aws_security_group" "file-upload-sg" {
  name        = "rds-sg"
  description = "Security group for RDS"
  vpc_id      = aws_vpc.file-upload-vpc.id

  ingress {
    from_port   = 0
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

   egress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

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
  skip_final_snapshot = true
  vpc_security_group_ids = [aws_security_group.file-upload-sg.id]
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