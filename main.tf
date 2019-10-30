# Defining provider


# Defining AWS providers
provider "aws" {
    region = "${var.aws_region}"
}

# Get AWS account details
data "aws_caller_identity" "current" {}


# Read Existing SNS topic from user input
data "aws_sns_topic" "SNSTopic" {
  name = "${var.SNSTopic}"
}


# Creates Cloudwatch event rule for SQS Rule
resource "aws_cloudwatch_event_rule" "TASQRule" {
    description = "Limit Monitor Solution - Rule for TA SQS events" 
    event_pattern = <<PATTERN
            {
          "account": [
            "${data.aws_caller_identity.current.account_id}"
          ],
          "source": [
            "aws.trustedadvisor",
            "limit-monitor-solution"
          ],
          "detail-type": [
            "Trusted Advisor Check Item Refresh Notification",
            "Limit Monitor Checks"
          ],
          "detail": {
            "status": [
              "WARN",
              "ERROR",
              "OK"

            ],
            "check-item-detail": {
              "Service": [ "${var.events_check_services}" ]
            }
          }
        }
        PATTERN
}

# Event target for TASQRule 
resource "aws_cloudwatch_event_target" "sns" {
    rule  = "${aws_cloudwatch_event_rule.TASQRule.name}"
    target_id = "LimitMonitorSQSTarget"
    arn = "${aws_sqs_queue.EventQueue.arn}"
}

# Creates Cloudwatch event rule for SNS Rule
resource "aws_cloudwatch_event_rule" "TASNSRule" {
    description = "Limit Monitor Solution - Rule for TA SNS events"
    event_pattern = <<PATTERN
      {
          "account": [
           "${data.aws_caller_identity.current.account_id}"
          ],
          "source": [
            "aws.trustedadvisor",
            "limit-monitor-solution"
          ],
          "detail-type": [
            "Trusted Advisor Check Item Refresh Notification",
            "Limit Monitor Checks"
          ],
          "detail": {
            "status": ["OK","WARN","ERROR"],
            "check-item-detail": {
              "Service": ["${var.events_check_services}"]
            }
          }
        }
        PATTERN
}


# Event target for TASNSRule
resource "aws_cloudwatch_event_target" "sqs" {
    rule  = "${aws_cloudwatch_event_rule.TASNSRule.name}"
    target_id = "LimitMonitorSQSTarget"
    arn =  "${data.aws_sns_topic.SNSTopic.arn}"
    input_transformer  {
      input_paths = { "limitdetails"="$.detail.check-item-detail", "time"="$.time","account"="$.account"}
      input_template = <<INPUT_TEMPLATE_EOF
        {
          "AWS-Account" : <account>,
          "Iimestamp" : <time>,
          "Limit-Details" : <limitdetails>
        }
        INPUT_TEMPLATE_EOF
    }
}


#
# Limit summarizer resources
# [EventQueue, DeadLetterQueue, EventQueuePolicy, QueuePollSchedule,
# SummarizerInvokePermission, LimitSummarizer, LimitSummarizerRole, SummaryDDB]
#

# Event Queue
resource "aws_sqs_queue" "EventQueue" {
    redrive_policy            = "{\"deadLetterTargetArn\":\"${aws_sqs_queue.DeadLetterQueue.arn}\",\"maxReceiveCount\":3}"
    visibility_timeout_seconds = 60
    message_retention_seconds   = 86400 #1 day retention
}

resource "aws_sqs_queue" "DeadLetterQueue" {
    message_retention_seconds = 604800 #7 day retention
}

resource "aws_sqs_queue_policy" "EventQueuePolicy" {
  queue_url = "${aws_sqs_queue.EventQueue.id}"

  policy  = <<POLICY
    {
      "Version":  "2012-10-17",
      "Id" :  "LimitMonitorSQSPolicy",
      "Statement" : [
        {
          "Sid":  "LimitMonitorCWEventsAccess",
          "Effect": "Allow",
          "Principal":  "*",
          "Action": "sqs:SendMessage",
          "Resource": "${aws_sqs_queue.EventQueue.arn}"
        }
      ]
    }
    POLICY
}

resource "aws_cloudwatch_event_rule" "QueuePollSchedule" {
  description = "Limit Monitor Solution - Schedule to poll SQS queue"
  schedule_expression = "rate(5 minutes)"
  
}


resource "aws_cloudwatch_event_target" "QueuePollScheduleTarget" {
  rule  = "${aws_cloudwatch_event_rule.QueuePollSchedule.name}"
  target_id = "SqsPollRate"
  arn     = "${aws_lambda_function.LimitSummarizer.arn}"
}




resource "aws_lambda_permission" "SummarizerInvokePermission" {
  function_name = "${aws_lambda_function.LimitSummarizer.function_name}"
  action  =  "lambda:InvokeFuntion"
  principal = "events.amazonaws.com"
  source_arn  = "${aws_cloudwatch_event_rule.QueuePollSchedule.arn}"

  
}


resource "aws_lambda_function" "LimitSummarizer" {
  description = "Serverless Limit Monitor - Lambda function to summarize service limit usage"
  environment {
    variables = {
      LIMIT_REPORT_TBL  = "${aws_dynamodb_table.SummaryDDB.id}"
      SQS_URL   = "${aws_sqs_queue.EventQueue.id}"
      MAX_MESSAGES  = "10"
      MAX_LOOPS = "10"
      ANONYMOUS_DATA =  "${var.SendAnonymousData}"
      SOLUTION  = "SO0005"
      UUID  = "${aws_lambda_function.LimtrHelperFunction.arn}"
      LOG_LEVEL =  "INFO" #change to WARN, ERROR or DEBUG as needed

    }
  }
  function_name = "LimitSummarizer"
  handler = "index.handler"
  role  = "${aws_iam_role.LimitSummarizerRole.arn}"
  filename = "${var.package_limitsummerizer}"
  runtime = "nodejs8.10"
  timeout = 300
}




resource "aws_iam_role" "LimitSummarizerRole" {
  path  = "/"
 assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
  }

data "aws_iam_policy_document" "LimitSummarizerPolicyDoc" {
  statement {
    sid = "1"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = [
      "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/*"
    ]
  }
  statement {
    actions = [
       "sqs:DeleteMessage",
       "sqs:ReceiveMessage"
    ]
    resources = ["${aws_sqs_queue.EventQueue.arn}"]
  }
  statement {
    actions = [
      "dynamodb:GetItem",
      "dynamodb:PutItem"
    ]
    resources =[  
      "arn:aws:dynamodb:${var.aws_region}:${data.aws_caller_identity.current.account_id}:table/${aws_dynamodb_table.SummaryDDB.id}"
    ]
  }
  
}

resource "aws_iam_policy" "LimitSummarizerPolicy" {
  path  = "/"
  policy  = "${data.aws_iam_policy_document.LimitSummarizerPolicyDoc.json}"
  
}

  
resource "aws_iam_role_policy_attachment" "LimitSummarizerPolicyAttachment" {
  role  = "${aws_iam_role.LimitSummarizerRole.name}"
  policy_arn  = "${aws_iam_policy.LimitSummarizerPolicy.arn}"
  
}

// have to work on this dynammo db
resource "aws_dynamodb_table" "SummaryDDB" {
  name = "SummaryDB"

  // Deletion policy 
  hash_key  = "MessageId"
  range_key = "TimeStamp"
  billing_mode  = "PROVISIONED"
  write_capacity  = "2"
  read_capacity = "2"
  server_side_encryption {
    enabled = true
  }
  attribute {
    name  = "TimeStamp"
    type  = "S"
  }
  attribute {
    name  = "MessageId"
    type  = "S"
  }
  ttl {
    attribute_name  = "ExpiryTime"
    enabled = true
  }
  tags =  {
    Solution = "Serverless-Limit-Monitor"
  }
  
}





resource "aws_cloudwatch_event_rule" "TARefreshSchedule" {
  description = "Limit Monitor Solution - Schedule to refresh TA checks"
  schedule_expression = "${var.CronSchedule}"
  
}

resource "aws_cloudwatch_event_target" "TARefreshScheduleTarget" {
    rule  = "${aws_cloudwatch_event_rule.TARefreshSchedule.name}"
    target_id = "TARefreshRate"
    arn =  "${aws_lambda_function.TARefresher.arn}"
}

resource "aws_lambda_function" "TARefresher" {
  function_name = "TARefresher"
  description = "Serverless Limit Monitor - Lambda function to summarize service limits"
  environment {
    variables = {
      AWS_SERVICES  =  "${var.events_check_services}" 
      LOG_LEVEL     = "INFO"
    }
  }
  handler = "index.handler"
  role  = "${aws_iam_role.TARefresherRole.arn}"
  filename  = "${var.package_tarefresher}"
  runtime = "nodejs8.10"
  timeout = "300"
  
}


resource "aws_iam_role" "TARefresherRole" {
  path  = "/"
 assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
  }


data "aws_iam_policy_document" "TARefresherRolePolicyDoc" {
  
  statement {
    sid = "1"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = [
      "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/*"
    ]
  }
  statement {
    actions = [
       "support:*"
    ]
    resources = ["*"]
  }
  statement {
    actions = [
      "servicequotas:GetAWSDefaultServiceQuota"
    ]
    resources = ["*"]
  }
  
}

resource "aws_iam_policy" "TARefresherPolicy" {
  path  = "/"
  policy  = "${data.aws_iam_policy_document.TARefresherRolePolicyDoc.json}"
  
}

  
resource "aws_iam_role_policy_attachment" "TARefresherPolicyAttachment" {
  role  = "${aws_iam_role.TARefresherRole.name}"
  policy_arn  = "${aws_iam_policy.TARefresherPolicy.arn}"
  
}


  #
  # Helper resources
  # LimtrHelperFunction, GetUUID, EstablishTrust,
  # AccountAnonymousData, SSMParameter, LimtrHelperRole
  #

resource "aws_lambda_function" "LimtrHelperFunction" {
  function_name = "LimtrHelperFunction"
  description = "This function generates UUID, establishes cross account trust on CloudWatch Event Bus and sends anonymous metric"
  handler = "index.handler"
  environment {
    variables = {
      LOG_LEVEL = "INFO" #change to WARN, ERROR or DEBUG as needed

    }
  }
  filename  = "${var.package_limithelperfunction}"
  runtime = "nodejs8.10"
  timeout = "300"
  role = "${aws_iam_role.LimitSummarizerRole.arn}"
}


resource "aws_iam_role" "LimtrHelperRole" {
  path  = "/"
 assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
  }


data "aws_iam_policy_document" "LimtrHelperRolePolicyDoc" {
  statement {
    sid = "1"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = [
      "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/*"
    ]
  }
  statement {
    actions = [
      "events:PutPermission",
      "events:RemovePermission"
    ] 
    resources = [
      "arn:aws:events:${var.aws_region}:${data.aws_caller_identity.current.account_id}:event-bus/default"
    ]
  }
  statement {
    actions = [
      "ssm:GetParameters",
      "ssm:PutParameter"
    ]
    resources = [ 
      "arn:aws:ssm:${var.aws_region}:${data.aws_caller_identity.current.account_id}:parameter/*"
      ]
  }
  
}

resource "aws_iam_policy" "LimtrHelperPolicy" {
  path  = "/"
  policy  = "${data.aws_iam_policy_document.LimtrHelperRolePolicyDoc.json}"
  
}

  
resource "aws_iam_role_policy_attachment" "LimtrHelperPolicyAttachment" {
  role  = "${aws_iam_role.LimtrHelperRole.name}"
  policy_arn  = "${aws_iam_policy.LimtrHelperPolicy.arn}"
  
}

resource "aws_lambda_permission" "TARefresherInvokePermission" {
  function_name = "${aws_lambda_function.TARefresher.function_name}"
  action  =   "lambda:InvokeFunction"
  principal = "events.amazonaws.com"
  source_arn  = "${aws_cloudwatch_event_rule.TARefreshSchedule.arn}"
}



### Nested stack 


resource "aws_lambda_function" "LimitMonitorFunction" {
  function_name = "LimitMonitorFunction"
  description = "This function generates UUID, establishes cross account trust on CloudWatch Event Bus and sends anonymous metric"
  handler = "index.handler"
  environment {
    variables = {
      LOG_LEVEL = "INFO" #change to WARN, ERROR or DEBUG as needed
      LIMIT_THRESHOLD = "${var.threshold_percentage}"

    }
  }
  filename  = "${var.package_limitmonitorfuncion}"
  runtime = "nodejs8.10"
  timeout = "300"
  role = "${aws_iam_role.LimitMonitorRole.arn}"
}







resource "aws_iam_role" "LimitMonitorRole" {
  path  = "/"
 assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
  }


data "aws_iam_policy_document" "LimitMonitorRolePolicyDoc" {
  statement {
    sid = "1"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = [
      "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/*"
    ]
  }
  statement {
    actions = [
      "servicequotas:GetServiceQuota",
      "servicequotas:GetAWSDefaultServiceQuota",
      "cloudwatch:GetMetricData",
      "events:PutEvents"
    ] 
    resources = [
      "*"
    ]
  }  
}

resource "aws_iam_policy" "LimitMonitorPolicy" {
  path  = "/"
  policy  = "${data.aws_iam_policy_document.LimitMonitorRolePolicyDoc.json}"
  
}

  
resource "aws_iam_role_policy_attachment" "LimitMonitorPolicyAttachment" {
  role  = "${aws_iam_role.LimitMonitorRole.name}"
  policy_arn  = "${aws_iam_policy.LimitMonitorPolicy.arn}"
  
}

resource "aws_cloudwatch_event_rule" "LimitCheckSchedule" {
  description = "Limit Monitor Solution - Rule to perform limit checks"
  schedule_expression = "${var.CronSchedule}"
  
}



resource "aws_cloudwatch_event_target" "LimitCheckScheduleTarget" {
    rule  = "${aws_cloudwatch_event_rule.LimitCheckSchedule.name}"
    target_id = "LimitSchedule"
    arn =  "${aws_lambda_function.LimitMonitorFunction.arn}"
}


resource "aws_lambda_permission" "LimitCheckInvokePermission" {
  function_name = "${aws_lambda_function.TARefresher.function_name}"
  action  =   "lambda:InvokeFunction"
  principal = "events.amazonaws.com"
  source_arn  = "${aws_cloudwatch_event_rule.LimitCheckSchedule.arn}"
}

