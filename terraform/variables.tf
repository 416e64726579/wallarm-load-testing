
variable "aws_region" {
  type    = string
  default = "eu-central-1"
}

variable "vpc_cidr_block" {
  type    = string
  default = "10.0.0.0/16"
}

variable "az_a" {
  type    = string
  default = "eu-central-1a"
}

variable "subnet_a_cidr_block" {
  type    = string
  default = "10.0.0.0/24"
}

variable "az_b" {
  type    = string
  default = "eu-central-1b"
}

variable "subnet_b_cidr_block" {
  type    = string
  default = "10.0.1.0/24"
}

variable "backend_ami_id" {
  type    = string
  default = "ami-080df3f56add7eca7"
}

variable "backend_instance_type" {
  type    = string
  default = "t3.2xlarge"
}

variable "wrk_ami_id" {
  type    = string
  default = "ami-080df3f56add7eca7"
}

variable "wrk_instance_type" {
  type    = string
  default = "t3.2xlarge"
}

variable "wallarm_node_ami_id" {
  type    = string
  default = "ami-013611266c0d59caf"
}

variable "waf_node_instance_type" {
  type    = string
  default = "t3.2xlarge"
}
