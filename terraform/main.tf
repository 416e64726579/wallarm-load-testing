
provider "aws" {
  region = var.aws_region
}

#
# Define a Key Pair to be used for both backend and WAF instances.
#
resource "aws_key_pair" "mykey" {
  key_name   = "tf-wallarm-load-key"
  public_key = var.key_pair
}

# #
# # Request a spot instance at $0.03
# #
# resource "aws_spot_instance_request" "waf_spot_request" {
#   ami           = var.wallarm_node_ami_id
#   spot_price    = "0.3"
#   instance_type = var.waf_node_instance_type
#
#   tags = {
#     Name = "waf_spot_request"
#   }
# }

#
# Create IAM Role for CloudWatch Agent
#
resource "aws_iam_role" "agent_iam_role" {
  name               = "AmazonCloudWatch-Load"
  assume_role_policy = <<-EOF
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": "sts:AssumeRole",
        "Principal": {
          "Service": "ec2.amazonaws.com"
        },
        "Effect": "Allow",
        "Sid": ""
      }
    ]
  }
  EOF
}

#
# Create IAM Policy for CloudWatch Agent
#
resource "aws_iam_role_policy" "agent_iam_policy" {
  name = "AmazonCloudWatch-Load"
  role = aws_iam_role.agent_iam_role.id

  policy = <<-EOF
  {
      "Version": "2012-10-17",
      "Statement": [
          {
              "Effect": "Allow",
              "Action": [
                  "cloudwatch:PutMetricData",
                  "ec2:DescribeVolumes",
                  "ec2:DescribeTags",
                  "logs:PutLogEvents",
                  "logs:DescribeLogStreams",
                  "logs:DescribeLogGroups",
                  "logs:CreateLogStream",
                  "logs:CreateLogGroup"
              ],
              "Resource": "*"
          },
          {
              "Effect": "Allow",
              "Action": [
                  "ssm:GetParameter"
              ],
              "Resource": "arn:aws:ssm:*:*:parameter/AmazonCloudWatch-*"
          }
      ]
  }
  EOF
}

#
# Create IAM Profile for CloudWatch Agent Role
#
resource "aws_iam_instance_profile" "agent_iam_profile" {
  name = "AmazonCloudWatch-Load"
  role = "${aws_iam_role.agent_iam_role.name}"
}

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

resource "aws_subnet" "public_a" {
  vpc_id                  = "${aws_vpc.my_vpc.id}"
  cidr_block              = var.subnet_a_cidr_block
  availability_zone       = var.az_a
  map_public_ip_on_launch = true
  tags = {
    Name = "tf-wallarm-load-subnet-a"
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
# Configure SG for Backend instances
#
resource "aws_security_group" "backend_sg" {
  name   = "tf-wallarm-load-backend"
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
  name   = "tf-wallarm-load-waf-elb"
  vpc_id = "${aws_vpc.my_vpc.id}"

  ingress {
    from_port   = 80
    to_port     = 80
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

# #
# # Configure ELB instance for Backend instances.
# #
# resource "aws_elb" "backend_elb" {
#   name = "tf-wallarm-load-backend"
#   security_groups = [
#     "${aws_security_group.backend_sg.id}"
#   ]
#   subnets = [
#     "${aws_subnet.public_a.id}"
#   ]
#
#   cross_zone_load_balancing = true
#   health_check {
#     healthy_threshold   = 2
#     unhealthy_threshold = 2
#     timeout             = 3
#     interval            = 30
#     target              = "HTTP:80/"
#   }
#   listener {
#     lb_port           = 80
#     lb_protocol       = "http"
#     instance_port     = "80"
#     instance_protocol = "http"
#   }
# }

# #
# # Configure ELB instance for WAF instances.
# #
# resource "aws_elb" "wallarm_elb" {
#   name = "tf-wallarm-load-walarm"
#   security_groups = [
#     "${aws_security_group.wallarm_asg_sg.id}"
#   ]
#   subnets = [
#     "${aws_subnet.public_a.id}"
#   ]
#
#   cross_zone_load_balancing = true
#   health_check {
#     healthy_threshold   = 2
#     unhealthy_threshold = 2
#     timeout             = 3
#     interval            = 30
#     target              = "HTTP:80/"
#   }
#   listener {
#     lb_port           = 80
#     lb_protocol       = "http"
#     instance_port     = "80"
#     instance_protocol = "http"
#   }
# }

#
# Configure NLB instance for WAF nodes.
#
resource "aws_lb" "wallarm_asg_nlb" {
  name               = "tf-wallarm-load-asg-nlb"
  internal           = false
  load_balancer_type = "network"
  subnets = [
    "${aws_subnet.public_a.id}"
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

#
# Launch Configuration for wrk instances.
#
resource "aws_launch_configuration" "wrk_launch_config" {

  image_id      = var.wrk_ami_id
  instance_type = var.wrk_instance_type
  # spot_price           = "0.3"
  iam_instance_profile = "${aws_iam_instance_profile.agent_iam_profile.name}"
  key_name             = "tf-wallarm-load-key"
  security_groups      = ["${aws_security_group.wrk_sg.id}"]
  user_data            = <<-EOF
#cloud-config

runcmd:
 - apt-get update
 - apt-get install -y build-essential libssl-dev git zlib1g-dev
 - git clone https://github.com/giltene/wrk2.git
 - cd wrk2
 - make
 - cp wrk /usr/local/bin
 - mkdir /etc/cloudwatch/
 - curl -O https://s3.${var.aws_region}.amazonaws.com/amazoncloudwatch-agent-${var.aws_region}/debian/amd64/latest/amazon-cloudwatch-agent.deb
 - dpkg -i -E ./amazon-cloudwatch-agent.deb
 - /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s
 - 'echo "net.ipv4.ip_local_port_range=10024 60999" >> /etc/sysctl.conf'
 - 'echo "* soft nofile 1000000\n* hard nofile 1000000" >> /etc/security/limits.conf'
 - sysctl -p
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
  vpc_zone_identifier  = ["${aws_subnet.public_a.id}"]

  tag {
    key                 = "Name"
    value               = "tf-wallarm-load-wrk"
    propagate_at_launch = true
  }
}

#
# Launch Configuration for Backend instances.
#
resource "aws_launch_configuration" "backend_launch_config" {

  image_id      = var.backend_ami_id
  instance_type = var.backend_instance_type
  # spot_price           = "0.3"
  iam_instance_profile = "${aws_iam_instance_profile.agent_iam_profile.name}"
  key_name             = "tf-wallarm-load-key"
  security_groups      = ["${aws_security_group.backend_sg.id}"]
  user_data            = <<-EOF
#cloud-config

write_files:
 - path: /etc/nginx/custom-nginx.conf
   owner: root:root
   permissions: '0644'
   content: |
    user www-data;
    worker_processes auto;
    worker_rlimit_nofile 320000;
    pid /run/nginx.pid;
    include /etc/nginx/modules-enabled/*.conf;

    events {
      worker_connections 20000;
      multi_accept on;
      use epoll;
    }

    http {

      ##
      # Basic Settings
      ##

      sendfile on;
      tcp_nopush on;
      tcp_nodelay on;
      keepalive_timeout 30;
      types_hash_max_size 2048;
      server_tokens off;
      reset_timedout_connection on;
      send_timeout 5;
      client_max_body_size 0;
      proxy_request_buffering off;
      proxy_http_version 1.1;
      proxy_set_header Connection "";
      keepalive_requests 100000;

      include /etc/nginx/mime.types;
      default_type application/octet-stream;

      ##
      # SSL Settings
      ##

      ssl_protocols TLSv1 TLSv1.1 TLSv1.2; # Dropping SSLv3, ref: POODLE
      ssl_prefer_server_ciphers on;

      ##
      # Logging Settings
      ##
      access_log /var/log/nginx/access.log;
      error_log /var/log/nginx/error.log;

      ##
      # Gzip Settings
      ##

      gzip on;

      ##
      # Virtual Host Configs
      ##

      include /etc/nginx/conf.d/*.conf;
      include /etc/nginx/sites-enabled/*;
    }
runcmd:
 - curl -sSL https://get.docker.com/ | sh
 - docker pull awallarm/bknd
 - apt-get update -y && apt-get install nginx -y
 - mkdir /etc/cloudwatch/
 - curl -O https://s3.${var.aws_region}.amazonaws.com/amazoncloudwatch-agent-${var.aws_region}/debian/amd64/latest/amazon-cloudwatch-agent.deb
 - dpkg -i -E ./amazon-cloudwatch-agent.deb
 - /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s
 - 'echo "net.ipv4.ip_local_port_range=10024 60999" >> /etc/sysctl.conf'
 - 'echo "* soft nofile 1000000\n* hard nofile 1000000" >> /etc/security/limits.conf'
 - sysctl -p
 - mv /etc/nginx/custom-nginx.conf /etc/nginx/nginx.conf
 - sed -i '0,/404;/{s/404;/404;\n                keepalive_requests 100000;/}' /etc/nginx/sites-available/default
 - sed -i 's#listen 80 default_server;#listen 80 default_server reuseport;#g' /etc/nginx/sites-enabled/default
 - sed -i '26 a Restart=on-failure\nRestartSec=5s' /lib/systemd/system/nginx.service
 - systemctl daemon-reload
 - systemctl start nginx
 - systemctl restart nginx
 EOF
}

#
# ASG for Backend instances
#
resource "aws_autoscaling_group" "backend_asg" {
  name                 = "tf-backend_asg-${aws_launch_configuration.backend_launch_config.name}"
  launch_configuration = "${aws_launch_configuration.backend_launch_config.name}"
  min_size             = "1"
  max_size             = "1"
  min_elb_capacity     = "1"
  vpc_zone_identifier  = ["${aws_subnet.public_a.id}"]
  # load_balancers       = ["${aws_elb.backend_elb.id}"]

  tag {
    key                 = "Name"
    value               = "tf-wallarm-load-backend"
    propagate_at_launch = true
  }
}

data "aws_instances" "backend" {
  depends_on = ["aws_autoscaling_group.backend_asg"]

  filter {
    name   = "tag:Name"
    values = ["tf-wallarm-load-backend"]
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
  iam_instance_profile = "${aws_iam_instance_profile.agent_iam_profile.name}"
  key_name             = "tf-wallarm-load-key"
  security_groups      = ["${aws_security_group.wallarm_asg_sg.id}"]
  user_data            = <<-EOF
#cloud-config

write_files:
 - path: /etc/nginx/nginx.conf
   owner: root:root
   permissions: '0644'
   content: |
    user www-data;
    worker_processes auto;
    worker_rlimit_nofile 320000;
    pid /run/nginx.pid;
    include /etc/nginx/modules-enabled/*.conf;

    events {
      worker_connections 20000;
      multi_accept on;
      use epoll;
    }

    http {

      ##
      # Basic Settings
      ##

      sendfile on;
      tcp_nopush on;
      tcp_nodelay on;
      keepalive_timeout 30;
      types_hash_max_size 2048;
      server_tokens off;
      reset_timedout_connection on;
      send_timeout 5;
      client_max_body_size 0;
      proxy_request_buffering off;
      proxy_http_version 1.1;
      proxy_set_header Connection "";
      keepalive_requests 100000;

      include /etc/nginx/mime.types;
      default_type application/octet-stream;

      ##
      # SSL Settings
      ##

      ssl_protocols TLSv1 TLSv1.1 TLSv1.2; # Dropping SSLv3, ref: POODLE
      ssl_prefer_server_ciphers on;

      ##
      # Logging Settings
      ##
      access_log /var/log/nginx/access.log;
      error_log /var/log/nginx/error.log;

      ##
      # Gzip Settings
      ##

      gzip on;

      ##
      # Virtual Host Configs
      ##

      include /etc/nginx/conf.d/*.conf;
      include /etc/nginx/sites-enabled/*;
    }
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
     resolver 10.0.0.2 valid=30s;
     resolver_timeout 20s;
     upstream backend {
       server ${element(data.aws_instances.backend.private_ips, 0)};
       keepalive 10000;
     }
     map $remote_addr $wallarm_mode_real {
     default block;
       include /etc/nginx/scanner-ips.conf;
     }
     server {
       listen 80 default_server reuseport backlog=10000;
       server_name _;
       wallarm_acl default;
       wallarm_mode $wallarm_mode_real;

       # wallarm_parse_response off;
       # wallarm_parser_disable base64;
       # wallarm_parser_diIftopsable xml;
       # wallarm_parser_disable cookie;
       # wallarm_parser_disable zlib;
       # wallarm_parser_disable htmljs;
       # wallarm_parser_disable json;
       # wallarm_parser_disable multipart;
       # wallarm_parser_disable percent;
       # wallarm_parser_disable urlenc;
       # wallarm_parse_html_response off;
       # wallarm_process_time_limit 1;
       # wallarm_process_time_limit_block off;

       location /healthcheck {
         return 200;
       }
       location / {
         # setting the address for request forwarding
         proxy_pass http://backend;
         proxy_set_header Host $host;
         proxy_set_header X-Real-IP $remote_addr;
         proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

         proxy_http_version 1.1;
         proxy_set_header Connection "";
         keepalive_requests 100000;

         set_real_ip_from 10.0.0.0/8;
         real_ip_header X-Forwarded-For;
       }
     }
runcmd:
 - /usr/share/wallarm-common/addnode --force -H ${var.wallarm_api_domain} -u ${var.deploy_username} -p ${var.deploy_password} --name `hostname`
 - 'echo "sync_blacklist:" >> /etc/wallarm/node.yaml'
 - 'echo "  nginx_url: http://127.0.0.9/wallarm-acl" >> /etc/wallarm/node.yaml'
 - mkdir /var/cache/nginx/
 - chown www-data /var/cache/nginx/
 - [ sed, -i, -Ee, 's/^#(.*sync-blacklist.*)/\1/', /etc/cron.d/wallarm-node-nginx ]
 - mkdir /etc/cloudwatch/
 - curl -O https://s3.${var.aws_region}.amazonaws.com/amazoncloudwatch-agent-${var.aws_region}/debian/amd64/latest/amazon-cloudwatch-agent.deb
 - dpkg -i -E ./amazon-cloudwatch-agent.deb
 - /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s
 - 'echo "net.ipv4.ip_local_port_range=10024 60999" >> /etc/sysctl.conf'
 - 'echo "net.core.somaxconn=10000" >> /etc/sysctl.conf'
 - 'echo "* soft nofile 1000000\n* hard nofile 1000000" >> /etc/security/limits.conf'
 - sysctl -p
 - sed -i '26 a Restart=on-failure\nRestartSec=5s' /lib/systemd/system/nginx.service
 - systemctl daemon-reload
 - systemctl start nginx
 - systemctl restart nginx
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
  target_group_arns    = ["${aws_lb_target_group.wallarm_asg_target_http.arn}"]
  # For ELB when it is not throttled
  # load_balancers       = ["${aws_elb.wallarm_elb.id}"]

  tag {
    key                 = "Name"
    value               = "tf-wallarm-load-waf-node"
    propagate_at_launch = true
  }
}
