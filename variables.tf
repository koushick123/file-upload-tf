variable "ec2_user_data" {
  type    = string
  default = <<-EOF
        #!/bin/sh
        echo 'Start My Script'
        echo '==============='
        apt-get update
        echo 'Install Docker'
        echo '=============='
        apt-get -y install docker.io        
        docker login -u koushick123 -p Platinum56
        docker pull koushick123/file-upload:3.0
        echo 'Install My-SQL Client'
        echo '====================='
        apt-get -y install mysql-client
        mysql --host="file-upload.c5isu4m0qrzm.ap-south-1.rds.amazonaws.com" --port="3306" --database="upload" --user="admin" --password="rdspassword" -e "CREATE TABLE file_table (FILE_ID int NOT NULL,FILE_NAME varchar(50) NOT NULL,FILE_UPLOAD_STATUS varchar(20) NOT NULL,FILE_UPLOAD_ERR_DESC varchar(500) DEFAULT NULL,PRIMARY KEY (FILE_ID)) ENGINE=InnoDB"
        docker run -p 80:8080 -d koushick123/file-upload:3.0
        EOF
}