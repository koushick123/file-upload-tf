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
  depends_on = [ aws_vpc_endpoint.dynamodb-vpc-endpoint]
}

data "aws_vpc_endpoint" "vpc_endpoint_s3_interface" {
  vpc_id = aws_vpc.file-upload-application-vpc.id
  service_name = "com.amazonaws.ap-south-1.s3"
  depends_on = [ aws_vpc_endpoint.s3-vpc-endpoint]
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

# File upload service policy to be used in EC2 instance profile which will run the file upload app
# This is an identity based policy
data "aws_iam_policy_document" "file-upload-service-policy" {
  statement {
    actions = ["dynamodb:PutItem","dynamodb:GetItem","secretsmanager:GetSecretValue","s3:PutObject","s3:GetObject","s3:ListBucket","sns:Publish"]
    effect = "Allow"
 
    resources = [aws_dynamodb_table.upload-table.arn, aws_s3_bucket.media-bucket-2024.arn, "${aws_s3_bucket.media-bucket-2024.arn}/*" ,aws_sns_topic.mail-upload-topic.arn, 
    aws_secretsmanager_secret.rds-login-endpint-secret.arn,
    aws_secretsmanager_secret.rds-login-username-secret.arn, 
    aws_secretsmanager_secret.rds-login-password-secret.arn,
    aws_secretsmanager_secret.sns-topic-arn.arn,
    aws_secretsmanager_secret.dynamodb-vpce.arn]
  }
}

# AWS SNS resource policy
data "aws_iam_policy_document" "sns-resource-policy" {
  statement {
    actions = ["sns:Publish"]
    effect = "Allow"

    principals {
      type = "AWS"
      identifiers = [aws_iam_role.file-upload-role.arn]
    }
    resources = [aws_sns_topic.mail-upload-topic.arn]
    sid = "stmt-1"
  }

  statement {
    actions = ["sns:Publish","sns:Subscribe","sns:DeleteTopic"]
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    resources = [aws_sns_topic.mail-upload-topic.arn]
    sid = "stmt-2"
    # Since Deny takes precedence , below condition is required to ensure above principal is excluded
    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = [aws_iam_role.file-upload-role.arn]
    }
    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = ["arn:aws:iam::556659523435:user/s3-user"]
    }
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
    # Below conditions are combined using AND operator
    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = [aws_iam_role.file-upload-role.arn]
    }
    condition {
      test = "StringNotEquals"
      variable = "aws:SourceVpce"
      values = [data.aws_vpc_endpoint.vpc_endpoint_dynamodb_interface.id]
    }
  }
}

#AWS S3 bucket resource policy

data "aws_iam_policy_document" "s3-bucket-resource-policy" {
  statement {
    actions = ["s3:PutObject","s3:GetObject","s3:ListBucket"]
    effect = "Allow"

    principals {
      type = "AWS"
      identifiers = [aws_iam_role.file-upload-role.arn]
    }

    resources = [aws_s3_bucket.media-bucket-2024.arn, "${aws_s3_bucket.media-bucket-2024.arn}/*"]
  }

  statement {
    actions = ["s3:PutObject","s3:GetObject","s3:ListBucket"]
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }
      
    resources = [aws_s3_bucket.media-bucket-2024.arn, "${aws_s3_bucket.media-bucket-2024.arn}/*"]
    # Since Deny takes precedence , below condition is required to ensure above principal is excluded
    # Below conditions will be combined using AND operator
    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = [aws_iam_role.file-upload-role.arn]
    }

    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = ["arn:aws:iam::556659523435:user/s3-user"]
    }

    condition {
      test = "StringNotEquals"
      variable = "aws:SourceVpce"
      values = [data.aws_vpc_endpoint.vpc_endpoint_s3_interface.id]
    }
  }
}

# AWS Secret Manager VPC Endpoint policy
data "aws_iam_policy_document" "secret-manager-vpc-endpoint-policy" {
  statement {
    actions = ["secretsmanager:GetSecretValue"]
    effect = "Allow"

    principals {
      type = "AWS"
      identifiers = [aws_iam_role.file-upload-role.arn]
    }

    resources = [aws_secretsmanager_secret.dynamodb-vpce.arn, aws_secretsmanager_secret.rds-login-endpint-secret.arn, aws_secretsmanager_secret.rds-login-password-secret.arn,
    aws_secretsmanager_secret.rds-login-username-secret.arn, aws_secretsmanager_secret.s3-vpce.arn, aws_secretsmanager_secret.sns-topic-arn.arn]
  }

  statement {
    actions = ["secretsmanager:GetSecretValue", "secretsmanager:PutSecretValue"]
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }
      
    resources = [aws_secretsmanager_secret.dynamodb-vpce.arn, aws_secretsmanager_secret.rds-login-endpint-secret.arn, aws_secretsmanager_secret.rds-login-password-secret.arn,
    aws_secretsmanager_secret.rds-login-username-secret.arn, aws_secretsmanager_secret.s3-vpce.arn, aws_secretsmanager_secret.sns-topic-arn.arn]
    # Since Deny takes precedence , below condition is required to ensure above principal is excluded
    # Below conditions will be combined using AND operator
    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = [aws_iam_role.file-upload-role.arn]
    }

    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = ["arn:aws:iam::556659523435:user/s3-user"]
    }

    condition {
      test = "StringNotEquals"
      variable = "aws:SourceVpce"
      values = [aws_vpc_endpoint.secret-manager-vpc-endpoint.id]
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
    actions = ["secretsmanager:GetSecretValue","secretsmanager:PutSecretValue"]
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }
      
    resources = [aws_secretsmanager_secret.rds-login-username-secret.arn]
    # Since Deny takes precedence , below condition is required to ensure above principal is excluded
    # Below conditions will be combined using AND operator
    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = [aws_iam_role.file-upload-role.arn]
    }

    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = ["arn:aws:iam::556659523435:user/s3-user"]
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
    actions = ["secretsmanager:GetSecretValue","secretsmanager:PutSecretValue"]
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }
      
    resources = [aws_secretsmanager_secret.rds-login-password-secret.arn]
    # Since Deny takes precedence , below condition is required to ensure above principal is excluded
    # Below conditions will be combined using AND operator
    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = [aws_iam_role.file-upload-role.arn]
    }

    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = ["arn:aws:iam::556659523435:user/s3-user"]
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
    actions = ["secretsmanager:GetSecretValue","secretsmanager:PutSecretValue"]
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }
      
    resources = [aws_secretsmanager_secret.rds-login-endpint-secret.arn]
    # Since Deny takes precedence , below condition is required to ensure above principal is excluded
    # Below conditions will be combined using AND operator
    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = [aws_iam_role.file-upload-role.arn]
    }

    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = ["arn:aws:iam::556659523435:user/s3-user"]
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
    actions = ["secretsmanager:GetSecretValue","secretsmanager:PutSecretValue"]
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }
      
    resources = [aws_secretsmanager_secret.sns-topic-arn.arn]
    # Since Deny takes precedence , below condition is required to ensure above principal is excluded
    # Below conditions will be combined using AND operator
    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = [aws_iam_role.file-upload-role.arn]
    }

    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = ["arn:aws:iam::556659523435:user/s3-user"]
    }
  }
}

# AWS Secret dynamodbvpcsecret resource policy

data "aws_iam_policy_document" "secret-manager-dynamodbvpce-resource-policy" {
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
    actions = ["secretsmanager:GetSecretValue","secretsmanager:PutSecretValue"]
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }
      
    resources = [aws_secretsmanager_secret.dynamodb-vpce.arn]
    # Since Deny takes precedence , below condition is required to ensure above principal is excluded
    # Below conditions will be combined using AND operator
    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = [aws_iam_role.file-upload-role.arn]
    }

    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = ["arn:aws:iam::556659523435:user/s3-user"]
    }
  }
}

# AWS Secret s3bucketvpcesecret resource policy

data "aws_iam_policy_document" "secret-manager-s3vpce-resource-policy" {
  statement {
    actions = ["secretsmanager:GetSecretValue"]
    effect = "Allow"

    principals {
      type = "AWS"
      identifiers = [aws_iam_role.file-upload-role.arn]
    }

    resources = [aws_secretsmanager_secret.s3-vpce.arn]
  }

  statement {
    actions = ["secretsmanager:GetSecretValue","secretsmanager:PutSecretValue"]
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }
      
    resources = [aws_secretsmanager_secret.s3-vpce.arn]
    # Since Deny takes precedence , below condition is required to ensure above principal is excluded
    # Below conditions will be combined using AND operator
    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = [aws_iam_role.file-upload-role.arn]
    }

    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = ["arn:aws:iam::556659523435:user/s3-user"]
    }
  }
}

data "aws_route53_zone" "my-file-upload-route53-zone" {
  name         = "my-file-upload.com"
  private_zone = false
}
