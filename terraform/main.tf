
provider "aws" {
  region = var.aws_region
}

#
# Define a Key Pair to be used for both fh and WAF instances.
#
resource "aws_key_pair" "mykey" {
  key_name   = "tf-wallarm-load-key"
  public_key = var.key_pair
}

# #
# # Create IAM Role for CloudWatch Agent
# #
# resource "aws_iam_role" "agent_iam_role" {
#   name               = "CloudWatchAgentServer"
#   assume_role_policy = <<-EOF
#   {
#     "Version": "2012-10-17",
#     "Statement": [
#       {
#         "Action": "sts:AssumeRole",
#         "Principal": {
#           "Service": "ec2.amazonaws.com"
#         },
#         "Effect": "Allow",
#         "Sid": ""
#       }
#     ]
#   }
#   EOF
# }
#
# #
# # Create IAM Policy for CloudWatch Agent
# #
# resource "aws_iam_role_policy" "agent_iam_policy" {
#   name = "agent_iam_policy"
#   role = aws_iam_role.agent_iam_role.id
#
#   policy = <<-EOF
#   {
#       "Version": "2012-10-17",
#       "Statement": [
#           {
#               "Effect": "Allow",
#               "Action": [
#                   "cloudwatch:PutMetricData",
#                   "ec2:DescribeVolumes",
#                   "ec2:DescribeTags",
#                   "logs:PutLogEvents",
#                   "logs:DescribeLogStreams",
#                   "logs:DescribeLogGroups",
#                   "logs:CreateLogStream",
#                   "logs:CreateLogGroup"
#               ],
#               "Resource": "*"
#           },
#           {
#               "Effect": "Allow",
#               "Action": [
#                   "ssm:GetParameter"
#               ],
#               "Resource": "arn:aws:ssm:*:*:parameter/AmazonCloudWatch-*"
#           }
#       ]
#   }
#   EOF
# }

# #
# # Create IAM Profile for CloudWatch Agent Role
# #
# resource "aws_iam_instance_profile" "agent_iam_profile" {
#   name = "agent_iam_profile"
#   role = "${aws_iam_role.agent_iam_role.name}"
# }

#
# Configure VPC, subnets, routing table and Internet Gateway resources.
#
resource "aws_vpc" "my_vpc" {
  cidr_block           = var.vpc_cidr_block
  enable_dns_hostnames = true
  tags = {
    Name = "tf-wallarm-load"
  }
}

# #
# # Request a spot instance at $0.03
# #
# resource "aws_spot_instance_request" "waf_spot_request" {
#   ami = var.wallarm_node_ami_id
#   # spot_price    = "0.3"
#   instance_type = var.waf_node_instance_type
#
#   tags = {
#     Name = "waf_spot_request"
#   }
# }


# #
# # Request a spot instance at $0.03
# #
# resource "aws_launch_template" "spot_launch_template" {
#   name = "spot_launch_template"
#
#   iam_instance_profile {
#     name = "${aws_iam_instance_profile.agent_iam_profile.name}"
#   }
#
#   instance_market_options {
#     market_type = "spot"
#
#     spot_options {
#       max_price          = "0.03"
#       spot_instance_type = "persistent"
#     }
#   }
# }

resource "aws_subnet" "public_a" {
  vpc_id                  = "${aws_vpc.my_vpc.id}"
  cidr_block              = var.subnet_a_cidr_block
  availability_zone       = var.az_a
  map_public_ip_on_launch = true
  tags = {
    Name = "tf-wallarm-load-subnet-a"
  }
}

resource "aws_subnet" "public_b" {
  vpc_id                  = "${aws_vpc.my_vpc.id}"
  cidr_block              = var.subnet_b_cidr_block
  availability_zone       = var.az_b
  map_public_ip_on_launch = true
  tags = {
    Name = "tf-wallarm-load-subnet-b"
  }
}

resource "aws_internet_gateway" "my_vpc_igw" {
  vpc_id = "${aws_vpc.my_vpc.id}"
  tags = {
    Name = "tf-wallarm-load"
  }
}

resource "aws_route_table" "my_vpc_public" {
  vpc_id = "${aws_vpc.my_vpc.id}"
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = "${aws_internet_gateway.my_vpc_igw.id}"
  }
  tags = {
    Name = "tf-wallarm-load"
  }
}

resource "aws_route_table_association" "my_vpc_a_public" {
  subnet_id      = "${aws_subnet.public_a.id}"
  route_table_id = "${aws_route_table.my_vpc_public.id}"
}

resource "aws_route_table_association" "my_vpc_b_public" {
  subnet_id      = "${aws_subnet.public_b.id}"
  route_table_id = "${aws_route_table.my_vpc_public.id}"
}

#
# Configure SG for wrk instances.
#
resource "aws_security_group" "wrk_sg" {
  name   = "tf-wallarm-load-wrk"
  vpc_id = "${aws_vpc.my_vpc.id}"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

#
# Configure SG for fasthttp instances.
#
resource "aws_security_group" "fh_sg" {
  name   = "tf-wallarm-load-fh"
  vpc_id = "${aws_vpc.my_vpc.id}"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

#
# Configure SG for Wallarm WAF nodes.
#
resource "aws_security_group" "wallarm_asg_sg" {
  name   = "tf-wallarm-load-waf-asg"
  vpc_id = "${aws_vpc.my_vpc.id}"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

#
# Configure SG for Wallarm LB instance.
#
resource "aws_security_group" "wallarm_elb_sg" {
  name   = "tf-wallarm-load-waf-nlb"
  vpc_id = "${aws_vpc.my_vpc.id}"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

#
# Configure ELB instance for fasthttp instances.
#
resource "aws_elb" "fh_elb" {
  name = "tf-wallarm-load-fh"
  security_groups = [
    "${aws_security_group.fh_sg.id}"
  ]
  subnets = [
    "${aws_subnet.public_a.id}",
    "${aws_subnet.public_b.id}"
  ]

  cross_zone_load_balancing = true
  health_check {
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 3
    interval            = 30
    target              = "HTTP:80/"
  }
  listener {
    lb_port           = 80
    lb_protocol       = "http"
    instance_port     = "80"
    instance_protocol = "http"
  }
}

#
# Configure NLB instance for WAF nodes.
#
resource "aws_lb" "wallarm_asg_nlb" {
  name               = "tf-wallarm-load-asg-nlb"
  internal           = false
  load_balancer_type = "network"
  subnets = [
    "${aws_subnet.public_a.id}",
    "${aws_subnet.public_b.id}"
  ]

  enable_deletion_protection = false
}

#
# Configure HTTP and HTTPS target groups for the NLB load balancer.
#
resource "aws_lb_target_group" "wallarm_asg_target_http" {
  name     = "tf-wallarm-load-asg-target-http"
  port     = 80
  protocol = "TCP"
  vpc_id   = "${aws_vpc.my_vpc.id}"
  stickiness {
    enabled = false
    type    = "lb_cookie"
  }
}

resource "aws_lb_target_group" "wallarm_asg_target_https" {
  name     = "tf-wallarm-load-asg-target-https"
  port     = 443
  protocol = "TCP"
  vpc_id   = "${aws_vpc.my_vpc.id}"
  stickiness {
    enabled = false
    type    = "lb_cookie"
  }
}

#
# Configure HTTP and HTTPS listeners for the NLB load balancer.
#
resource "aws_lb_listener" "wallarm_asg_nlb_http" {
  load_balancer_arn = "${aws_lb.wallarm_asg_nlb.arn}"
  port              = "80"
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = "${aws_lb_target_group.wallarm_asg_target_http.arn}"
  }
}

resource "aws_lb_listener" "wallarm_asg_nlb_https" {
  load_balancer_arn = "${aws_lb.wallarm_asg_nlb.arn}"
  port              = "443"
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = "${aws_lb_target_group.wallarm_asg_target_https.arn}"
  }
}

#
# Launch Configuration for wrk instances.
#
resource "aws_launch_configuration" "wrk_launch_config" {

  image_id      = var.wrk_ami_id
  instance_type = var.wrk_instance_type
  # spot_price           = "0.3"
  # iam_instance_profile = "${aws_iam_instance_profile.agent_iam_profile.name}"
  key_name        = "tf-wallarm-load-key"
  security_groups = ["${aws_security_group.wrk_sg.id}"]
  user_data       = <<-EOF
#cloud-config

runcmd:
 - sudo apt-get update
 - sudo apt-get install -y build-essential libssl-dev git zlib1g-dev
 - git clone https://github.com/giltene/wrk2.git
 - cd wrk2
 - make
 - sudo cp wrk /usr/local/bin
 - mkdir /etc/cloudwatch/
 - curl -O https://s3.${var.aws_region}.amazonaws.com/amazoncloudwatch-agent-${var.aws_region}/debian/amd64/latest/amazon-cloudwatch-agent.deb
 - sudo dpkg -i -E ./amazon-cloudwatch-agent.deb
 - sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s
 EOF
}

#
# ASG for wrk instances.
#
resource "aws_autoscaling_group" "wrk_asg" {
  name                 = "tf-wrk_asg-${aws_launch_configuration.wrk_launch_config.name}"
  launch_configuration = "${aws_launch_configuration.wrk_launch_config.name}"
  min_size             = "1"
  max_size             = "1"
  min_elb_capacity     = "1"
  vpc_zone_identifier  = ["${aws_subnet.public_a.id}", "${aws_subnet.public_b.id}"]

  # launch_template {
  #   id      = "${aws_launch_template.spot_launch_template.id}"
  #   version = "$Latest"
  # }

  tag {
    key                 = "Name"
    value               = "tf-wallarm-load-wrk"
    propagate_at_launch = true
  }
}

#
# Launch Configuration for fasthttp instances.
#
resource "aws_launch_configuration" "fh_launch_config" {

  image_id      = var.fasthttp_ami_id
  instance_type = var.fasthttp_instance_type
  # spot_price           = "0.3"
  # iam_instance_profile = "${aws_iam_instance_profile.agent_iam_profile.name}"
  key_name        = "tf-wallarm-load-key"
  security_groups = ["${aws_security_group.fh_sg.id}"]
  user_data       = <<-EOF
#cloud-config

runcmd:
 - curl -sSL https://get.docker.com/ | sh
 - docker run -d --restart=on-failure -p 80:8080 --name bknd awallarm/bknd:latest
 - mkdir /etc/cloudwatch/
 - curl -O https://s3.${var.aws_region}.amazonaws.com/amazoncloudwatch-agent-${var.aws_region}/debian/amd64/latest/amazon-cloudwatch-agent.deb
 - dpkg -i -E ./amazon-cloudwatch-agent.deb
 - /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s
 - echo 'net.ipv4.ip_local_port_range=10024 60999' >> /etc/sysctl.conf
 - echo "* soft nofile 25000\n* hard nofile 50000" >> /etc/security/limits.conf
 - ulimit -u unlimited
 - sysctl -p
 EOF
}

#
# ASG for fasthttp instances.
#
resource "aws_autoscaling_group" "fh_asg" {
  name                 = "tf-fh_asg-${aws_launch_configuration.fh_launch_config.name}"
  launch_configuration = "${aws_launch_configuration.fh_launch_config.name}"
  min_size             = "1"
  max_size             = "1"
  min_elb_capacity     = "1"
  vpc_zone_identifier  = ["${aws_subnet.public_a.id}", "${aws_subnet.public_b.id}"]
  load_balancers       = ["${aws_elb.fh_elb.id}"]

  # launch_template {
  #   id      = "${aws_launch_template.spot_launch_template.id}"
  #   version = "$Latest"
  # }

  tag {
    key                 = "Name"
    value               = "tf-wallarm-load-fh"
    propagate_at_launch = true
  }
}

#
# Launch Configuration for Wallarm WAF nodes.
#
resource "aws_launch_configuration" "wallarm_launch_config" {
  lifecycle { create_before_destroy = true }

  image_id      = var.wallarm_node_ami_id
  instance_type = var.waf_node_instance_type
  # spot_price           = "0.3"
  # iam_instance_profile = "${aws_iam_instance_profile.agent_iam_profile.name}"
  key_name        = "tf-wallarm-load-key"
  security_groups = ["${aws_security_group.wallarm_asg_sg.id}"]
  user_data       = <<-EOF
#cloud-config

write_files:
 - path: /etc/nginx/nginx.conf
   owner: root:root
   permissions: '0644'
   content: "${file("nginx.conf")}"
 - path: /etc/nginx/scanner-ips.conf
   owner: root:root
   permissions: '0644'
   content: "${file("scanner-ips.conf")}"
 - path: /etc/nginx/conf.d/wallarm-acl.conf
   owner: root:root
   permissions: '0644'
   content: |
    wallarm_acl_db default {
      wallarm_acl_path /var/cache/nginx/wallarm_acl_default;
      wallarm_acl_mapsize 64m;
    }
    server {
      listen 127.0.0.9:80;
      server_name localhost;
      allow 127.0.0.0/8;
      deny all;
      access_log off;
      location /wallarm-acl {
        wallarm_acl default;
        wallarm_acl_api on;
      }
    }
 - path: /etc/nginx/sites-available/default
   owner: root:root
   permissions: '0644'
   content: |
     map $remote_addr $wallarm_mode_real {
     default block;
       include /etc/nginx/scanner-ips.conf;
     }
     server {
       listen 80 default_server reuseport;
       server_name _;
       wallarm_acl default;
       wallarm_mode $wallarm_mode_real;
       # wallarm_instance 1;
       location /healthcheck {
         return 200;
       }
       location / {
         # setting the address for request forwarding
         proxy_pass http://${aws_elb.fh_elb.dns_name};
         proxy_set_header Host $host;
         proxy_set_header X-Real-IP $remote_addr;
         proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
         set_real_ip_from 172.31.0.0/16;
         real_ip_header X-Forwarded-For;
       }
     }
     server {
       listen 443 ssl default_server reuseport;
       server_name _;
       wallarm_acl default;
       ssl_protocols TLSv1.2;
       ssl_ciphers         HIGH:!aNULL:!MD5;
       ssl_certificate /etc/nginx/cert.pem;
       ssl_certificate_key /etc/nginx/key.pem;
       wallarm_mode block;
       # wallarm_instance 1;
       location /healthcheck {
         return 200;
       }
       location / {
         # setting the address for request forwarding
         proxy_pass http://${aws_elb.fh_elb.dns_name};
         proxy_set_header Host $host;
         proxy_set_header X-Real-IP $remote_addr;
         proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
       }
     }
 - path: /etc/nginx/key.pem
   # This is a self-signed SSL certificate
   owner: root:root
   permissions: '0600'
   content: |
    -----BEGIN PRIVATE KEY-----
    MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDB6BggatWgySvo
    0M0k5+AzRaTFgSm32AZndx7v7qTbhJy8SaGgrdBz6rRLd/kFY3c3uT/yYtNGsKlb
    watSUHnyHTvwmfiQaZzJ4A97WqYn8bLke/seYRSYe+MYWLzykBlyS8qaauiGDLoF
    QhJ7UYlSJs1PJOqgu3NGIPy5PHVkknk/ykEQPIfjXE7pHftdC6/F+hkzyNlXehfo
    q3GHlDI/8UPexvg+QbluwtOe8ypZXbSqnA29Vpy8gw2Gyl9504El6r62EFL0lM5Y
    U1E7e1sUp1QiMTvqN1HGtuvOcfDS7VjgjgYKkJ+YL1vUKFTeMSq+fA+i1MPPsu/I
    RnbfCnD7AgMBAAECggEAWyKMhF/x+9nRK2FHqbrZov9ui+1DAEcl62cPQVF2Zj4T
    tGMe9ff7ax+6kWXXwnKXS7djmLZd+nF5h8ikjtGIHwUicNjM/ILG0BLg8+cNBOUS
    YVTsF8Ek/u3rNDwwwgh8DT4WATGSC77bhzEgopkV42idQj9ljxnK+gDzBtSlkBh9
    j7iL6C7II8dcnElu4HVY8Iuu67F9dsmNW76NJ7iqXuQZ3wQ4VUZ2FfaThBfHnPlq
    4k1bekCR5x5DuTPe90M4B4GIqxbBVo3yge1zvvVBY/O2dZDNyFgrxOQ2LQ4+4Y2P
    x7rD9QH7eLj03HU+GP0LLDeDWyIbEcZpmy7PvicYYQKBgQDxPof//pQm72FiPfmh
    WTRzuWWdp72159jp6n/y8FP6IJNDhSA8p7FlffJ8cbQl9zpSwNeMg8MOv3ZAYNtz
    /sYL17QKNLikRw1kom6PB2X738LVpVhoiYA5WtIufJoYxYdp665MhQygz480K/F1
    QEyQLBTedpAdF8waeohRDe/SMwKBgQDNxFZSBIU4Sk3MznbJ3gov2WlRpbz4g9V4
    4dRi3NEQrnbx8i0+7NOvzv+iouvXcm+lkXfLcluWCUhaIFW+dUQ3zAgPvWdWRQOO
    WNvikEuwz+LlGmY0KO5hVatvAGPv7HL4iXCB6/4ZQdTzZsWBO8MXhyCiTIUYHd3+
    y9pIFX9uGQKBgESU2UbeUbHL5axvH/NNj8rCTvAFyrnW4mSFZMBksArwjczpIKP9
    rEHFD1VvYZ5VbUAvUFfC8YXUykI9BsYwDI87UBSCrmcNR/Ju9u00VjrHfvULn1mA
    lXI4rn3GsGwQY5GqDY/1VwS0XOqg/3CsyddGoNwpaojKxhxU70HTq3TfAoGADJ5U
    uNTkIo6T9NJYgIqoT0Ti64nha9AR4EbhEmr+OyqnyrCSS8CUPrzP+nZJRj4TULD6
    CrTpnurU0AoZmANy+oT9nZF869JxpGIYoe09Zwtom6ohyGMWM0vgpn78ofL7Hfi3
    uI/zVjMuTvrnc8Rpc2DrBGjy5Ia4XW685RzEYskCgYEArXW5DdZuRQxX9CJmGoWK
    Sjxp1QLXzrHzhSeBTTYKWrP0YHBaDHhM6LBzbI21dAeV4qOKfDIduNWrzqSsxRcp
    PwyquUKmj6Bv0j64TwQKnHmsawVd4wB6FhpMUchNxszIKBhsLXXSdRJjpsL5Hfvt
    PG4rVUW5036CMHgnlP5zZLk=
    -----END PRIVATE KEY-----
 - path: /etc/nginx/cert.pem
   # This is a self-signed SSL certificate
   owner: root:root
   permissions: '0644'
   content: |
    -----BEGIN CERTIFICATE-----
    MIIDVjCCAj4CCQDwQNr36lh8ZjANBgkqhkiG9w0BAQsFADBtMQswCQYDVQQGEwJV
    UzELMAkGA1UECAwCQ0ExEjAQBgNVBAcMCVNhbiBNYXRlbzEQMA4GA1UECgwHV2Fs
    bGFybTELMAkGA1UECwwCSVQxHjAcBgNVBAMMFSoudmljdG9yLWdhcnR2aWNoLmNv
    bTAeFw0yMDAyMjkwNjQyNDdaFw0yMTAyMjgwNjQyNDdaMG0xCzAJBgNVBAYTAlVT
    MQswCQYDVQQIDAJDQTESMBAGA1UEBwwJU2FuIE1hdGVvMRAwDgYDVQQKDAdXYWxs
    YXJtMQswCQYDVQQLDAJJVDEeMBwGA1UEAwwVKi52aWN0b3ItZ2FydHZpY2guY29t
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwegYIGrVoMkr6NDNJOfg
    M0WkxYEpt9gGZ3ce7+6k24ScvEmhoK3Qc+q0S3f5BWN3N7k/8mLTRrCpW8GrUlB5
    8h078Jn4kGmcyeAPe1qmJ/Gy5Hv7HmEUmHvjGFi88pAZckvKmmrohgy6BUISe1GJ
    UibNTyTqoLtzRiD8uTx1ZJJ5P8pBEDyH41xO6R37XQuvxfoZM8jZV3oX6Ktxh5Qy
    P/FD3sb4PkG5bsLTnvMqWV20qpwNvVacvIMNhspfedOBJeq+thBS9JTOWFNRO3tb
    FKdUIjE76jdRxrbrznHw0u1Y4I4GCpCfmC9b1ChU3jEqvnwPotTDz7LvyEZ23wpw
    +wIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAhfJ8OCvF3cMJrKr2RTIpq7impRvjY
    lNaT/hP5S8Y0YHtWXdxP/vMk0tZSD7NAKcd0Zz4ocnezYhNxqeZcL5Vd8EUXqGpE
    hZ7r02pkHwIglprF6iuQY/qRE566zUjcVQieYqTb4rki42fSVAck7lv+LIg+CCOg
    C1dz11284x/8hyy06M1zbtET0oniEnZuDFOtbMTLUqR9jLDtqJsgOgcD7Y3Y+WXI
    9DnIZdXRjK+d45ytY6c9SqV/ienxbvjx2G3DG2kiYGfTPQOUVC+UX8KtqNEDpxOZ
    ooqMBlOXYxLJ2I9UcCu21Wj+CXJAPPbj/UZ79t59nC2yB5OmrniOFsMC
    -----END CERTIFICATE-----
runcmd:
 - /usr/share/wallarm-common/addnode --force -H ${var.wallarm_api_domain} -u ${var.deploy_username} -p ${var.deploy_password} --name `hostname`
 - 'echo "sync_blacklist:" >> /etc/wallarm/node.yaml'
 - 'echo "  nginx_url: http://127.0.0.9/wallarm-acl" >> /etc/wallarm/node.yaml'
 - mkdir /var/cache/nginx/
 - chown www-data /var/cache/nginx/
 - nginx -t
 - service nginx start
 - service nginx reload
 - [ sed, -i, -Ee, 's/^#(.*sync-blacklist.*)/\1/', /etc/cron.d/wallarm-node-nginx ]
 - mkdir /etc/cloudwatch/
 - curl -O https://s3.${var.aws_region}.amazonaws.com/amazoncloudwatch-agent-${var.aws_region}/debian/amd64/latest/amazon-cloudwatch-agent.deb
 - sudo dpkg -i -E ./amazon-cloudwatch-agent.deb
 - sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s
 EOF
}

#
# ASG configuration for Wallarm WAF nodes.
#
resource "aws_autoscaling_group" "wallarm_waf_asg" {
  lifecycle { create_before_destroy = true }

  name                 = "tf-wallarm-load-waf-asg-${aws_launch_configuration.wallarm_launch_config.name}"
  launch_configuration = "${aws_launch_configuration.wallarm_launch_config.name}"
  min_size             = "1"
  max_size             = "1"
  min_elb_capacity     = "1"
  vpc_zone_identifier  = ["${aws_subnet.public_a.id}"]
  target_group_arns    = ["${aws_lb_target_group.wallarm_asg_target_http.arn}", "${aws_lb_target_group.wallarm_asg_target_https.arn}"]

  enabled_metrics = [
    "GroupMinSize",
    "GroupMaxSize",
    "GroupDesiredCapacity",
    "GroupInServiceInstances",
    "GroupTotalInstances"
  ]
  metrics_granularity = "1Minute"

  # launch_template {
  #   id      = "${aws_launch_template.spot_launch_template.id}"
  #   version = "$Latest"
  # }

  tag {
    key                 = "Name"
    value               = "tf-wallarm-load-waf-node"
    propagate_at_launch = true
  }
}

#
# Print out the DNS name of created NLB instance.
#
output "waf_nlb_dns_name" {
  value = [aws_lb.wallarm_asg_nlb.dns_name]
}
