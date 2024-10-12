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
    actions = ["dynamodb:PutItem","dynamodb:GetItem","secretsmanager:GetSecretValue","s3:PutObject","s3:GetObject","s3:ListBucket","sns:Publish"]
    effect = "Allow"
 
    resources = [aws_dynamodb_table.upload-table.arn, aws_s3_bucket.media-bucket-2024.arn, "${aws_s3_bucket.media-bucket-2024.arn}/*" ,aws_sns_topic.mail-upload-topic.arn, 
    aws_secretsmanager_secret.rds-login-endpint-secret.arn,
    aws_secretsmanager_secret.rds-login-username-secret.arn, 
    aws_secretsmanager_secret.rds-login-password-secret.arn,
    aws_secretsmanager_secret.sns-topic-arn.arn]
  }
}

# DynamoDB resource policy 

data "aws_iam_policy_document" "dynamodb-resource-policy" {
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

  statement {
    actions = ["dynamodb:PutItem","dynamodb:GetItem"]
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    resources = [aws_dynamodb_table.upload-table.arn]
    # Since Deny takes precedence , below condition is required to ensure above principal is excluded
    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = [aws_iam_role.file-upload-role.arn]
    }
  }
}

# AWS Secret usernamesecret resource policy

data "aws_iam_policy_document" "secret-manager-usernamesecret-resource-policy" {
  statement {
    actions = ["secretsmanager:GetSecretValue"]
    effect = "Allow"

    principals {
      type = "AWS"
      identifiers = [aws_iam_role.file-upload-role.arn]
    }

    resources = [aws_secretsmanager_secret.rds-login-username-secret.arn]
  }

  statement {
    actions = ["secretsmanager:GetSecretValue"]
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }
      
    resources = [aws_secretsmanager_secret.rds-login-username-secret.arn]
    # Since Deny takes precedence , below condition is required to ensure above principal is excluded
    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = [aws_iam_role.file-upload-role.arn]
    }
  }
}

# AWS Secret passwordsecret resource policy

data "aws_iam_policy_document" "secret-manager-passwordsecret-resource-policy" {
  statement {
    actions = ["secretsmanager:GetSecretValue"]
    effect = "Allow"

    principals {
      type = "AWS"
      identifiers = [aws_iam_role.file-upload-role.arn]
    }

    resources = [aws_secretsmanager_secret.rds-login-password-secret.arn]
  }

  statement {
    actions = ["secretsmanager:GetSecretValue"]
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }
      
    resources = [aws_secretsmanager_secret.rds-login-password-secret.arn]
    # Since Deny takes precedence , below condition is required to ensure above principal is excluded
    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = [aws_iam_role.file-upload-role.arn]
    }
  }
}

# AWS Secret endpointsecret resource policy

data "aws_iam_policy_document" "secret-manager-endpointsecret-resource-policy" {
  statement {
    actions = ["secretsmanager:GetSecretValue"]
    effect = "Allow"

    principals {
      type = "AWS"
      identifiers = [aws_iam_role.file-upload-role.arn]
    }

    resources = [aws_secretsmanager_secret.rds-login-endpint-secret.arn]
  }

  statement {
    actions = ["secretsmanager:GetSecretValue"]
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }
      
    resources = [aws_secretsmanager_secret.rds-login-endpint-secret.arn]
    # Since Deny takes precedence , below condition is required to ensure above principal is excluded
    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = [aws_iam_role.file-upload-role.arn]
    }
  }
}

# AWS Secret mailuploadtopic resource policy

data "aws_iam_policy_document" "secret-manager-mailuploadtopic-resource-policy" {
  statement {
    actions = ["secretsmanager:GetSecretValue"]
    effect = "Allow"

    principals {
      type = "AWS"
      identifiers = [aws_iam_role.file-upload-role.arn]
    }

    resources = [aws_secretsmanager_secret.sns-topic-arn.arn]
  }

  statement {
    actions = ["secretsmanager:GetSecretValue"]
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }
      
    resources = [aws_secretsmanager_secret.sns-topic-arn.arn]
    # Since Deny takes precedence , below condition is required to ensure above principal is excluded
    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = [aws_iam_role.file-upload-role.arn]
    }
  }
}

data "aws_route53_zone" "my-file-upload-route53-zone" {
  name         = "my-file-upload.com"
  private_zone = false
}
