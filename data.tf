data "aws_vpc" "file-upload-vpc" {
  cidr_block = "10.100.0.0/16"
  depends_on = [ aws_vpc.file-upload-db-vpc ]
}

data "aws_db_instance" "file-upload-rds" {
  db_instance_identifier = "file-upload"
  depends_on = [ aws_db_instance.file-upload-rds ]
}

data "aws_sns_topic" "email-upload-topic" {
  name = "mail-upload-topic"
  depends_on = [ aws_sns_topic.mail-upload-topic ]
}

data "aws_vpc_endpoint" "vpc_endpoint_dynamodb_interface" {
  vpc_id = aws_vpc.file-upload-application-vpc.id
  service_name = "com.amazonaws.ap-south-1.dynamodb"
  depends_on = [ aws_vpc_endpoint.file-upload-endpoint ]
}

data "aws_iam_policy_document" "assume-role-policy" {
  statement {
    actions = ["sts:AssumeRole"]
    effect = "Allow"
  
    principals {
      type = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "file-upload-service-policy" {
  statement {
    actions = ["dynamodb:PutItem","dynamodb:GetItem","secretsmanager:GetSecretValue","sns:Publish","s3:ListBucket","s3:PutObject",
				"s3:GetObject"]
    effect = "Allow"
 
    resources = [aws_dynamodb_table.upload-table.arn, aws_s3_bucket.media-bucket-2024.arn, aws_sns_topic.mail-upload-topic.arn, aws_secretsmanager_secret.rds-login-endpint-secret.arn,
    aws_secretsmanager_secret.rds-login-username-secret.arn, aws_secretsmanager_secret.rds-login-password-secret.arn]

    condition {
      test = "StringEquals"
      variable = "aws:SourceVpce"
      values = [data.aws_vpc_endpoint.vpc_endpoint_dynamodb_interface.id]
    }
  }
}

data "aws_iam_policy_document" "dynamodb-policy-with-principal" {
  statement {
    actions = ["dynamodb:PutItem","dynamodb:GetItem"]
    effect = "Allow"
 
    principals {
      type = "AWS"
      identifiers = [aws_iam_role.file-upload-role.arn]
    }
    resources = [aws_dynamodb_table.upload-table.arn]

    condition {
      test = "StringEquals"
      variable = "aws:SourceVpce"
      values = [data.aws_vpc_endpoint.vpc_endpoint_dynamodb_interface.id]
    }
  }
}
