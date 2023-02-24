resource "aws_wafregional_rule" "ips" {
  count = length(var.ip_sets)

  name        = format("%s-ips-%d", var.web_acl_name, count.index)
  metric_name = format("%sIPs%d", var.web_acl_metric_name, count.index)

  predicate {
    data_id = var.ip_sets[count.index]
    negated = false
    type    = "IPMatch"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_wafregional_byte_match_set" "allowed_hosts" {
  name = format("%s-allowed-hosts", var.web_acl_name)

  dynamic "byte_match_tuples" {
    for_each = var.allowed_hosts
    content {

      # Even though the AWS Console web UI suggests a capitalized "host" data,
      # the data should be lower case as the AWS API will silently lowercase anyway.
      field_to_match {
        type = "HEADER"
        data = "host"
      }

      target_string = byte_match_tuples.value

      # See ByteMatchTuple for possible variable options.
      # See https://docs.aws.amazon.com/waf/latest/APIReference/API_ByteMatchTuple.html#WAF-Type-ByteMatchTuple-PositionalConstraint
      positional_constraint = "EXACTLY"

      # Use COMPRESS_WHITE_SPACE to prevent sneaking around regex filter with
      # extra or non-standard whitespace
      # See https://docs.aws.amazon.com/sdk-for-go/api/service/waf/#RegexMatchTuple
      text_transformation = "COMPRESS_WHITE_SPACE"
    }
  }
}

resource "aws_wafregional_rule" "allowed_hosts" {
  name        = format("%s-allowed-hosts", var.web_acl_name)
  metric_name = format("%sAllowedHosts", var.web_acl_metric_name)

  predicate {
    type    = "ByteMatch"
    data_id = aws_wafregional_byte_match_set.allowed_hosts.id
    negated = true
  }
}

resource "aws_wafregional_byte_match_set" "blocked_path_prefixes" {
  name = format("%s-blocked-path-prefixes", var.web_acl_name)

  dynamic "byte_match_tuples" {
    for_each = var.blocked_path_prefixes
    content {
      field_to_match {
        type = "URI"
      }

      target_string = byte_match_tuples.value

      # See ByteMatchTuple for possible variable options.
      # See https://docs.aws.amazon.com/waf/latest/APIReference/API_ByteMatchTuple.html#WAF-Type-ByteMatchTuple-PositionalConstraint
      positional_constraint = "STARTS_WITH"

      # Use COMPRESS_WHITE_SPACE to prevent sneaking around regex filter with
      # extra or non-standard whitespace
      # See https://docs.aws.amazon.com/sdk-for-go/api/service/waf/#RegexMatchTuple
      text_transformation = "COMPRESS_WHITE_SPACE"
    }
  }
}

resource "aws_wafregional_rule" "blocked_path_prefixes" {
  name        = format("%s-blocked-path-prefixes", var.web_acl_name)
  metric_name = format("%sBlockedPathPrefixes", var.web_acl_metric_name)

  predicate {
    type    = "ByteMatch"
    data_id = aws_wafregional_byte_match_set.blocked_path_prefixes.id
    negated = false
  }
}


resource "aws_wafv2_web_acl" "example" {
  name        = "managed-rule-example"
  description = "Example of a managed rule."
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "rule-1"
    priority = 1

    override_action {
      count {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"

        rule_action_override {
          action_to_use {
            count {}
          }

          name = "SizeRestrictions_QUERYSTRING"
        }

        rule_action_override {
          action_to_use {
            count {}
          }

          name = "NoUserAgent_HEADER"
        }

        scope_down_statement {
          geo_match_statement {
            country_codes = ["US", "NL"]
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = false
      metric_name                = "AWSManagedRulesCommonRuleSet"
      sampled_requests_enabled   = false
    }
  }

  rule {
    name     = "SQLInjectionQueryArguments"
    priority = 2

    action {
      block {}
    }

    statement {
      sqli_match_statement {

        field_to_match {
          all_query_arguments {
          }
        }

        text_transformation {
          priority = 1
          type     = "URL_DECODE"
        }

        text_transformation {
          priority = 2
          type     = "HTML_ENTITY_DECODE"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "SQLInjectionQueryArguments"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = false
    metric_name                = "WebACLMetric"
    sampled_requests_enabled   = false
  }

}
