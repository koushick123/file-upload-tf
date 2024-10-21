# AWS VPC for Application
# Create Application VPC
resource "aws_vpc" "file-upload-application-vpc" {
  cidr_block = "10.200.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support = true
  tags = {
    Name = "File-Upload-Application-VPC"
  }
}

# Security Group for Application
resource "aws_default_security_group" "default-sg-application" {
  vpc_id = aws_vpc.file-upload-application-vpc.id
  tags = {
    Name = "File-Upload-Application-SG"
  }
}

resource "aws_vpc_security_group_ingress_rule" "default-sg-application-ingress-ssh" {
  security_group_id = aws_default_security_group.default-sg-application.id
  ip_protocol = "tcp"
  from_port = 22
  to_port = 22
  cidr_ipv4 = "0.0.0.0/0"
}

resource "aws_vpc_security_group_ingress_rule" "default-sg-application-ingress-http" {
  security_group_id = aws_default_security_group.default-sg-application.id
  ip_protocol = "tcp"
  from_port = 80
  to_port = 80
  cidr_ipv4 = "0.0.0.0/0"
}

resource "aws_vpc_security_group_egress_rule" "default-sg-application-egress" {
  security_group_id = aws_default_security_group.default-sg-application.id
  ip_protocol = "All"
  from_port = -1
  to_port = -1
  cidr_ipv4 = "0.0.0.0/0"
}

# Route table for Application
resource "aws_default_route_table" "file-upload-application-route-table" {
  default_route_table_id  = aws_vpc.file-upload-application-vpc.default_route_table_id

  route {
    cidr_block = aws_vpc.file-upload-application-vpc.cidr_block
    gateway_id = "local"
  }

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.file-upload-application-igw.id
  }
  tags = {
    Name = "File-Upload-Application-RT"
  }
}

# Create a subnet within the Application VPC
resource "aws_subnet" "file-upload-application-subnet-az-1a" {
  vpc_id     = aws_vpc.file-upload-application-vpc.id
  cidr_block = "10.200.1.0/24"
  availability_zone = "ap-south-1a"
  tags = {
    Name = "File-Upload-Application-subnet"
  }
}

resource "aws_internet_gateway" "file-upload-application-igw" {
  vpc_id = aws_vpc.file-upload-application-vpc.id
  tags = {
    Name = "File-Upload-Application-IGW"
  }
}

#==========================================================================================================================================

# AWS EC2
# Create EC2
resource "aws_instance" "file-upload-instance" {
  tags = {
    Name = "File-Upload-Application"
  }
  ami = "ami-0dee22c13ea7a9a67"
  instance_type = "t2.micro"
  key_name = aws_key_pair.file-upload-key-pair.key_name
  subnet_id = aws_subnet.file-upload-application-subnet-az-1a.id
  vpc_security_group_ids = [ aws_default_security_group.default-sg-application.id ]
  associate_public_ip_address = true
  iam_instance_profile = "${aws_iam_instance_profile.file-upload-profile.name}"
}

# TLS Private Key
resource "tls_private_key" "file-upload-private-key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

# EC2 Key Pair
resource "aws_key_pair" "file-upload-key-pair" {
  key_name = "file-upload-key"
  public_key = tls_private_key.file-upload-private-key.public_key_openssh
}

# EC2 Instance profile
resource "aws_iam_instance_profile" "file-upload-profile" {
  name = "file-upload-profile"
  role = "${aws_iam_role.file-upload-role.name}"
}

#==========================================================================================================================================
# AWS RDS
# Create a database VPC
resource "aws_vpc" "file-upload-db-vpc" {
  cidr_block = "10.100.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support = true
  tags = {
    Name = "File-Upload-DB"
  }
}

# Security Group for database
resource "aws_default_security_group" "default-sg-rds" {
  vpc_id = aws_vpc.file-upload-db-vpc.id
  tags = {
    Name = "File-Upload-DB-SG"
  }
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

# Route table for database
resource "aws_default_route_table" "file-upload-route-table" {
  default_route_table_id  = aws_vpc.file-upload-db-vpc.default_route_table_id

  route {
    cidr_block = aws_vpc.file-upload-db-vpc.cidr_block
    gateway_id = "local"
  }

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.file-upload-igw.id
  }
  tags = {
    Name = "File-Upload-DB-RT"
  }
}

# Create a subnet within the database VPC
resource "aws_subnet" "file-upload-subnet-az-1a" {
  vpc_id     = aws_vpc.file-upload-db-vpc.id
  cidr_block = "10.100.1.0/24"
  availability_zone = "ap-south-1a"
  tags = {
    Name = "File-Upload-DB-Subnet"
  }
}

resource "aws_internet_gateway" "file-upload-igw" {
  vpc_id = aws_vpc.file-upload-db-vpc.id
  tags = {
    Name = "File-Upload-IGW-DB"
  }
}

resource "aws_subnet" "file-upload-subnet-az-1b" {
  vpc_id     = aws_vpc.file-upload-db-vpc.id
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

#==========================================================================================================================================
# AWS S3
# Create an S3 bucket
resource "aws_s3_bucket" "media-bucket-2024" {
  bucket = "media-bucket-2024"
}

# Disable Block Public Access Settings
resource "aws_s3_bucket_public_access_block" "my_bucket_public_access_block" {
  bucket = aws_s3_bucket.media-bucket-2024.id

  block_public_acls       = true  # Disable BlockPublicAcls
  ignore_public_acls       = true  # Allow ACLs
  block_public_policy      = true  # Disable BlockPublicPolicy
  restrict_public_buckets  = true  # Allow public bucket
}

# Create resource based policy
resource "aws_s3_bucket_policy" "media-bucket-resource-policy" {
  bucket = aws_s3_bucket.media-bucket-2024.id
  policy = data.aws_iam_policy_document.s3-bucket-resource-policy.json
}

#==========================================================================================================================================
# AWS Dynamo DB
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

# Create Dynamo DB resource based policy
resource "aws_dynamodb_resource_policy" "upload-table-policy" {
  policy = data.aws_iam_policy_document.dynamodb-resource-policy.json
  resource_arn = aws_dynamodb_table.upload-table.arn
  confirm_remove_self_resource_access = false
}

#==========================================================================================================================================
# IAM Access Policy
# Create IAM Policy role with specific access to resources (AWS RDS, DynamodDB, S3)
 resource "aws_iam_role" "file-upload-role" {
   description = "Role to be used by application for file upload"
  name = "file-upload-role"
  assume_role_policy = data.aws_iam_policy_document.assume-role-policy.json
}

resource "aws_iam_role_policy" "file_upload_role_policy" {
  name = "file-upload-role-policy"  
  role = "${aws_iam_role.file-upload-role.id}"
  policy = data.aws_iam_policy_document.file-upload-service-policy.json
}

#==========================================================================================================================================
# VPC Endpoint
# Create VPC Endpoint (Interface)
resource "aws_vpc_endpoint" "dynamodb-vpc-endpoint" {
  service_name = "com.amazonaws.ap-south-1.dynamodb"
  auto_accept = true
  vpc_id = aws_vpc.file-upload-application-vpc.id
  subnet_ids = [aws_subnet.file-upload-application-subnet-az-1a.id]
  vpc_endpoint_type = "Interface"
  security_group_ids = [aws_security_group.vpce-sg-application-vpc.id]
  #depends_on = [ aws_dynamodb_table.upload-table ]
}

# VPC Endpoint policy
resource "aws_vpc_endpoint_policy" "dynamodb-vpc-endpoint-policy" {
  vpc_endpoint_id = aws_vpc_endpoint.dynamodb-vpc-endpoint.id
  policy = data.aws_iam_policy_document.dynamodb-resource-policy.json
}

# VPC Endpoint for AWS S3
resource "aws_vpc_endpoint" "s3-vpc-endpoint" {
  service_name = "com.amazonaws.ap-south-1.s3"
  auto_accept = true
  vpc_id = aws_vpc.file-upload-application-vpc.id
  subnet_ids = [aws_subnet.file-upload-application-subnet-az-1a.id]
  vpc_endpoint_type = "Interface"
  private_dns_enabled = true
  dns_options {
    private_dns_only_for_inbound_resolver_endpoint = false
  }
  security_group_ids = [aws_security_group.vpce-sg-application-vpc.id]
}

# VPC Endpoint policy
resource "aws_vpc_endpoint_policy" "s3-vpc-endpoint-policy" {
  vpc_endpoint_id = aws_vpc_endpoint.s3-vpc-endpoint.id
  policy = data.aws_iam_policy_document.s3-bucket-resource-policy.json
}

#==========================================================================================================================================
# AWS Secret Manager
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

# Create AWS Secret Manager for SNS Topic
resource "aws_secretsmanager_secret" "sns-topic-arn" {
  name = "fileuploadtopicarnsecret"
  recovery_window_in_days = 0
}

# Create AWS Secret Manager for DynamoDB Endpoint
resource "aws_secretsmanager_secret" "dynamodb-vpce" {
  name = "dynamodbvpcesecret"
  recovery_window_in_days = 0
}

# Create AWS Secret Manager for DynamoDB Endpoint
resource "aws_secretsmanager_secret" "s3-vpce" {
  name = "s3bucketvpcesecret"
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

# Create AWS Secret values for SNS Topic
resource "aws_secretsmanager_secret_version" "sns-file-upload-topic-arn" {
  secret_id = aws_secretsmanager_secret.sns-topic-arn.id
  secret_string = aws_sns_topic.mail-upload-topic.arn
}

# Create AWS Secret values for Dynamo DB VPC Endpoint
resource "aws_secretsmanager_secret_version" "dynamodb-vpce" {
  secret_id = aws_secretsmanager_secret.dynamodb-vpce.id
  secret_string = aws_vpc_endpoint.dynamodb-vpc-endpoint.dns_entry[0]["dns_name"]
}

# Create AWS Secret values for AWS S3 VPC Endpoint
resource "aws_secretsmanager_secret_version" "s3-vpce" {
  secret_id = aws_secretsmanager_secret.s3-vpce.id
  secret_string = aws_vpc_endpoint.s3-vpc-endpoint.dns_entry[2]["dns_name"]
}

# Create AWS Secret Manager resource based policies for all its secrets
resource "aws_secretsmanager_secret_policy" "usernamesecretpolicy" {
  secret_arn = aws_secretsmanager_secret.rds-login-username-secret.arn
  policy = data.aws_iam_policy_document.secret-manager-usernamesecret-resource-policy.json
}

resource "aws_secretsmanager_secret_policy" "passwordsecretpolicy" {
  secret_arn = aws_secretsmanager_secret.rds-login-password-secret.arn
  policy = data.aws_iam_policy_document.secret-manager-passwordsecret-resource-policy.json
}

resource "aws_secretsmanager_secret_policy" "endpointsecretpolicy" {
  secret_arn = aws_secretsmanager_secret.rds-login-endpint-secret.arn
  policy = data.aws_iam_policy_document.secret-manager-endpointsecret-resource-policy.json
}

resource "aws_secretsmanager_secret_policy" "mailtopicsecretpolicy" {
  secret_arn = aws_secretsmanager_secret.sns-topic-arn.arn
  policy = data.aws_iam_policy_document.secret-manager-mailuploadtopic-resource-policy.json
}

resource "aws_secretsmanager_secret_policy" "dynamodbvpesecretpolicy" {
  secret_arn = aws_secretsmanager_secret.dynamodb-vpce.arn
  policy = data.aws_iam_policy_document.secret-manager-dynamodbvpce-resource-policy.json
}

resource "aws_secretsmanager_secret_policy" "s3vpesecretpolicy" {
  secret_arn = aws_secretsmanager_secret.s3-vpce.arn
  policy = data.aws_iam_policy_document.secret-manager-s3vpce-resource-policy.json
}

#==========================================================================================================================================
# AWS SNS Notification
# Create AWS SNS Topic and Subscription
resource "aws_sns_topic" "mail-upload-topic" {
  name = "mail-upload-topic"
}

resource "aws_sns_topic_subscription" "mail-upload-subscription" {
  topic_arn = data.aws_sns_topic.email-upload-topic.arn
  endpoint = "skoushicksuri@gmail.com"
  protocol = "email"
}

# SNS resource based policy
resource "aws_sns_topic_policy" "mail-upload-policy" {
  arn = data.aws_sns_topic.email-upload-topic.arn
  policy = data.aws_iam_policy_document.sns-resource-policy.json
}

#==========================================================================================================================================
# AWS Route53 record
# DNS A record to connect to EC2 Public IP

resource "aws_route53_record" "file-upload-route53-alias" {
  zone_id = data.aws_route53_zone.my-file-upload-route53-zone.zone_id
  name = "www.${data.aws_route53_zone.my-file-upload-route53-zone.name}"
  type = "A"
  ttl = "300"
  records = [aws_instance.file-upload-instance.public_ip]
}

#==========================================================================================================================================
# Security Group for AWS VPC Endpoint
# Create Security Group for VPC Endpoint to allow inbound traffic
resource "aws_security_group" "vpce-sg-application-vpc" {
  vpc_id = aws_vpc.file-upload-application-vpc.id
  tags = {
    Name = "VPC-Endpoint-SG"
  }
}

# Create Ingress rules
resource "aws_vpc_security_group_ingress_rule" "vpce-sg-ingress-https" {
  security_group_id = aws_security_group.vpce-sg-application-vpc.id
  ip_protocol = "tcp"
  from_port = 443
  to_port = 443
  referenced_security_group_id = aws_default_security_group.default-sg-application.id
}

# Create Egress rule
resource "aws_vpc_security_group_egress_rule" "vpce-sg-egress-all" {
  security_group_id = aws_security_group.vpce-sg-application-vpc.id
  ip_protocol = "All"
  from_port = -1
  to_port = -1
  referenced_security_group_id = aws_default_security_group.default-sg-application.id
}