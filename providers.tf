terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "5.66.0"
    }
  }
}

provider "aws" {
   region     = "ap-south-1"
   access_key = "<access-key>"
   secret_key = "<secret-key>"
}