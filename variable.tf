variable "aws_region" {
    description = "The AWS region to create things in."
    default = "us-east-1"
}


/*
variable "AccountList" {
    description = "List of comma-separated and double-quoted account numbers to monitor. If you leave this parameter blank, the solution will only monitor limits in the primary account. If you enter multiple secondary account IDs, you must also provide the primary account ID in this parameter."
    type = "string"
}
*/

variable "SNSEvents" {
    description = "List of alert levels to send email notifications. Must be double-quoted and comma separated. To disable email notifications, enter two comma separated blank double quotes (“”,””)."
    type = "list"
    default = ["WARN","ERROR"]
    
}

# MetricMap
variable "SendAnonymousData" {
    description =   "Metric Map / Send-Data"
    type = "string"
    default = "Yes"
}

variable "CronSchedule" {
    description =   "RefreshRate / Cronschedule"
    type    =   "string"
    default =   "rate(1 day)"
}

variable "s3_bucket" {
    description =   "Soruce code bucket name"
    type    =   "string"
    default =   "solutions"
  
}

variable "s3_key_prefix" {
    type = "string"
    default = "limit-monitor/v5.3.0"  
}

variable "template_bucket" {
    type = "string"
    default = "solutions-reference"  
}

variable "events_check_services" {
    type = "string"
    default = "'AutoScaling','CloudFormation','DynamoDB','EBS','EC2','ELB','IAM','Kinesis','RDS','Route53','SES','VPC'"
}


variable "threshold_percentage" {
    type    =   "string"
    default =   0.8
  
}


variable "SNSTopic" {
    type   =    "string"
    description = "Existing snstopic to integrate"
  
}


output "ServiceChecks" {
  description = "Service limits monitored in the account"
  value =   "${var.events_check_services}"
}

output "UUID" {
  description   =   "UUID for the deployment"
  value =   "${aws_lambda_function.LimtrHelperFunction.arn}"
}


