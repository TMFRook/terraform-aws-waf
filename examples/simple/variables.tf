variable "waf_acl_name" {
  type = string
}

variable "waf_acl_metric_name" {
  type = string
}

variable "vpc_azs" {
  type = list(string)
  default = ["us-east-1a", "us-east-1b"]
}
