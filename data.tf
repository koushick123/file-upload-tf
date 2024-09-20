data "aws_vpc" "file-upload-vpc" {
  cidr_block = "10.100.0.0/16"
  depends_on = [ aws_vpc.file-upload-vpc ]
}

# data "aws_defa" "file-upload-vpc-default-sg" {
#   filter {
#     name   = "group-name"
#     values = ["default"]
#   }
#   vpc_id = data.aws_vpc.file-upload-vpc.id
#   depends_on = [ aws_vpc.file-upload-vpc ]
# }

data "aws_db_instance" "file-upload-rds" {
  db_instance_identifier = "file-upload"
  depends_on = [ aws_db_instance.file-upload-rds ]
}