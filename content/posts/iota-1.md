---
title: "iota part 1 - building a self-hosted CloudTrail detection engine"
date: 2025-11-28T20:26:19Z
draft: false
toc: true
next: true
nomenu: false
notitle: false
---

## tl;dr

i'm building a lightweight detection engine called `iota`: https://github.com/bilals12/iota. it reads CloudTrail logs from S3, runs Python rules against them, and sends alerts to Slack. these are design notes on the core implementation, before we head for deployment. 

## why build?

CloudTrail logs sit in S3, and we need to run detections against them. as a security team, you have 3 options: buy (SaaS), hack (DIY), or build your own engine.

### SaaS

these platforms send your logs to their infrastructure (or you can host them as well), but you pay per GB/TB ingested. this gets expensive very fast. there are also proprietary rules which you can run, but those depend on the talent of their research engineering team. the last thing: these are very expensive tools, costing anywhere from $5k/month to $50k/month.

### DIY

anyone can technically set up the following chain:

```
CloudTrail → SNS topic → SQS queue → Lambda function
```

the issue arises with having to manage multiple AWS services and dealing with [Lambda cold starts + timeout issues](https://docs.aws.amazon.com/lambda/latest/dg/best-practices.html). it would also require having to manage state (hopefully not with DynamoDB, but at least PostgreSQL). this would suddenly balloon to more and more components, which means more things can break (with no one to fix them).

### bespoke detection engine

i went with building my own engine because of a few points that attracted me: nothing leaves my org's data control plane; i get to control costs (and keep them to a minimum), i can write my own rules, and the infrastructure becomes very simple. 

with SNS/SQS event-driven processing, `iota` can achieve 5-16 minutes total latency (mostly due to [CloudTrail's 5-15 minute delay](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-faq.html#cloudtrail-faq-how-often)). since i'm not focused on real-time blocking at this stage, this seems acceptable to me.

## design philosophy

i boiled everything down to a few core principles.

### simplicity over optimization

i'd rather have one component that's easy to reason about than a distributed system that's theoretically more efficient. SNS/SQS adds a little complexity (compared to the original S3-poller that i was writing), but the latency improvement is worth it. plus, i can manage all the infrastructure with Terraform.


### rules as code

i didn't want to force anyone to learn a DSL or a proprietary query language...if you can write Python, you can write a detection rule!

### fail obviously

when something breaks, i want a clear error message and a single place to look (pod logs). i don't want to have to hunt through CloudWatch Logs across several Lambda functions.

### local = production

i wanted local development to match production as closely as possible. if i can run `./bin/iota` locally with the same rules that run in production, debugging gets a lot easier.

## architecture

### high-level

```
CloudTrail writes to S3
  ↓
S3 bucket notifications → SNS Topic
  ↓
SNS Topic → SQS Queue (with dead letter queue)
  ↓
iota SQS processor receives notifications
  ↓
downloads .json.gz files from S3
  ↓
decompresses and parses JSON
  ↓
log processor classifies and normalizes events
  ↓
optional: data lake writes to S3 with partitioning
  ↓
runs Python rules against each event
  ↓
SQLite deduplication prevents alert fatigue
  ↓
sends alerts to Slack for detections
```

### components

so far, iota is made up of a few key components:

1. an SQS processor: this receives the S3 event notifications via SQS and extracts the bucket/key
2. a log processor: this downloads files, decompresses, and classifies events by service
3. a data lake writer: this can store processed events in S3 with hourly partitioning
4. a detection engine: this executes Python rules (via subprocess)
5. alert deduplication: an SQLite database that prevents duplicate alerts
6. an alert forwarder: routes alerts to Slack, stdout, or other outputs
7. a health checker: simple HTTP endpoints for Kubernetes liveness/readiness probes

all of this runs in a single Go binary inside a pod inside a cluster.

## key design decisions

### event-driven (SNS/SQS)

`iota` uses SNS/SQS for event-driven processing, instead of the original idea of polling S3. why?

for real-time(~) processing. when CloudTrail writes a log file to S3, S3 sends a notification to SNS, which delivers to SQS, and then `iota` can process it within seconds. we don't have to wait for next poll cycle any more!

CloudTrail also takes 5-15 minutes to write logs ([AWS CloudTrail FAQ](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-faq.html#cloudtrail-faq-how-often)). with event-driven processing, we can detect new files within seconds of them being written, so the total latency is still around 5-15 minutes (vs. 20+ minutes).

since we now only process files when they're actually created, `iota` doesn't waste time with API calls that lists thousands of objects every few minutes. and multiple `iota` pods can consume from the same SQS queue (since SQS handles [message distribution and timeouts automatically](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-scaling.html)).

the tradeoff is: more AWS components. SNS topic, SQS queue, DLQ, IAM permissions for all 3. the debugging becomes slightly more complex (did S3 send the notification? did SNS deliver it? did SQS receive it? did `iota` process it?), but each step does have clear error messages and CloudWatch metrics.

here is the implementation of the SQS processor (`internal/events/sqs_processor.go`):

```go
func (p *SQSProcessor) Process(ctx context.Context) error {
    for {
        result, err := p.client.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{
            QueueUrl:            aws.String(p.queueURL),
            MaxNumberOfMessages: aws.Int32(p.maxMessages),
            WaitTimeSeconds:     aws.Int32(p.waitTime),  // long polling: 20 seconds
            VisibilityTimeout:   aws.Int32(300),
        })

        for _, message := range result.Messages {
            // parse SNS message containing S3 notification
            var snsMessage struct {
                Type    string `json:"Type"`
                Message string `json:"Message"`
            }
            json.Unmarshal([]byte(*message.Body), &snsMessage)

            // extract S3 bucket and key from notification
            var s3Notification struct {
                Records []struct {
                    S3 struct {
                        Bucket struct{ Name string }
                        Object struct{ Key string }
                    }
                }
            }
            json.Unmarshal([]byte(snsMessage.Message), &s3Notification)

            // process the S3 object
            for _, record := range s3Notification.Records {
                p.handler(ctx, record.S3.Bucket.Name, record.S3.Object.Key)
            }

            // delete message after successful processing
            p.client.DeleteMessage(ctx, &sqs.DeleteMessageInput{
                QueueUrl:      aws.String(p.queueURL),
                ReceiptHandle: message.ReceiptHandle,
            })
        }
    }
}
```

[long polling](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-long-polling.html) means we're not constantly hitting the SQS API. whenever messages arrive, we get them immediately. when there are no messages, we wait 20 seconds before checking again. 

### rules as code

"rules" here are just Python scripts that follow a simple interface:

```python
def rule(event):
    """Transform the event into whatever shape you need for analysis."""
    return {
        "event": event,
        "user_type": event.get("userIdentity", {}).get("type"),
        "event_name": event.get("eventName"),
    }

def alert(event):
    """Return True if this event should trigger an alert."""
    if event.get("user_type") == "Root" and event.get("event_name") == "ConsoleLogin":
        return True
    return False

def title(event):
    return "AWS Root Account Login Detected"

def severity():
    return "CRITICAL"
```

the nice thing about Python is most security engineers already know it, so the barrier to entry isn't as high as it would be if they had to learn a proprietary DSL.

Python also has full language features for complex logic (IP address checks, CIDR matching, external API calls, etc), so that is available plus any `pip` package. 

the other good thing about Python rules is that you can test them locally. all you have to do is `python my-rule.py < event.json` and see what happens. no need to deploy anything just to test the rules.

the tradeoff here is: subprocess overhead. spawning a Python interpreter for each rule evaluation adds around 10-50ms of latency ([per eval](https://docs.python.org/3/library/subprocess.html)). for a typical batch of 100 events with 20 rules, that's 2000 subprocess calls, which can take 20-100 seconds. this is acceptable for now, since the primary bottleneck is still CloudTrail's delivery latency. TODO: compile rules once and reuse the intepreter? or rewrite hot-path rules in Go?

this is how the engine runs via subprocess:

```go
func (e *Engine) EvaluateRule(ctx context.Context, rulePath string, event map[string]interface{}) (*Detection, error) {
    eventJSON, _ := json.Marshal(event)

    cmd := exec.CommandContext(ctx, e.python, e.engineScript, rulePath)
    cmd.Stdin = strings.NewReader(string(eventJSON))

    output, err := cmd.Output()
    if err != nil {
        return nil, fmt.Errorf("rule execution failed: %w", err)
    }

    var detection Detection
    json.Unmarshal(output, &detection)
    return &detection, nil
}
```

it's sequential for now, but it would be great to parallelize with `goroutines` later.

### SQLite for dedup

SQLite here prevents alert fatigue by tracking which alerts we've already sent.

```sql
CREATE TABLE alerts (
    alert_id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL,
    dedup_string TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    alert_count INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(rule_id, dedup_string)
);
```

with SQLite, there isn't an external database to manage. the file can live on disk (or k8s `PersistentVolume`), and there are no network calls, connection pools, or additional managed database costs. 

the schema is also deliberately simple: i just need to track alert groups and prevent duplicates within a time window (60 minutes by default). 

re: performance, the local disk I/O is pretty fast. SQLite can also [handle thousands of writes per second](https://sqlite.org/fasterthanfs.html#write_performance_measurements), which is really good at this stage.

again, the tradeoff: i can't easily share dedup state across multiple `iota` pods without coordination, since SQLite is single-writer. but with SQS, each message is delivered once anyway, so multiple pods can run independently. they just won't share dedup state. if the same event triggers multiple alerts, SQS makes sure that we only process it once. the dedup is mainly for grouping similar alerts ("10 failed login attempts from IP 1.2.3.5"), instead of 10 separate alerts.

deduplication is so important! without it, a single suspicious activity ("100 failed API calls") would generate 100 separate Slack messages. that would be unacceptable.

### kubernetes + IRSA

`iota` is designed to run as a kubernetes deployment, with 1 pod. authentication to AWS uses IRSA (IAM Roles for Service Accounts).

Turo already runs Kubernetes for other services, so adding `iota` as another deployment becomes straightforward. `PersistentVolume` for the SQLite database, and pod restarts don't lose state. rolling updates work naturally here: code change -> new container built -> push to ECR/Docker Hub -> update image tag -> k8s handles rollout.

[IRSA](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html) is also very useful here, because i really like to avoid long-lived AWS credentials. the pod gets a temporary token from STS that expires after an hour. it's scoped to specific actions, so the IAM role only allows an S3 read on the CloudTrail bucket and nothing else. with automatic rotation, i don't need to manage credential lifecycles.

this is the `ServiceAccount` annotation:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: iota
  namespace: security
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/eks-cluster-iota
```

the IAM trust policy lets this specific `ServiceAccount` assume the role:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::123456789012:oidc-provider/oidc.eks.region.amazonaws.com/id/OIDC_ID"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "oidc.eks.region.amazonaws.com/id/OIDC_ID:sub": "system:serviceaccount:security:iota"
      }
    }
  }]
}
```

and the role permissions are minimal:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:ListBucket", "s3:GetBucketLocation"],
      "Resource": "arn:aws:s3:::cloudtrail-bucket"
    },
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": "arn:aws:s3:::cloudtrail-bucket/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "sqs:ReceiveMessage",
        "sqs:DeleteMessage",
        "sqs:GetQueueAttributes",
        "sqs:GetQueueUrl"
      ],
      "Resource": "arn:aws:sqs:us-east-1:123456789012:iota-cloudtrail-queue"
    },
    {
      "Effect": "Allow",
      "Action": ["kms:Decrypt", "kms:DescribeKey"],
      "Resource": "arn:aws:kms:us-east-1:123456789012:key/cloudtrail-key"
    }
  ]
}
```

so: just read CloudTrail logs, receive SQS messages, and decrypt KMS-encrypted files.

### core engine

the core of `iota` is written in Go.

i chose Go for a few reasons. one: the AWS SDK support is pretty good. [Go SDK v2](https://docs.aws.amazon.com/sdk-for-go/v2/developer-guide/welcome.html) has good S3 APIs and credential handling is very smooth with IRSA. 

i wanted a single, statically-linked binary, which Go compiles to and which i can then copy into a Docker container. the only runtime dependencies here are the Python interpreter (which i need for the rules).

`goroutines` and channels make it easy to implement concurrency, which will be needed to add parallelism down the line. 

## big TODOs

there are many things still left to build.

### parallel rule evaluation 

right now rules run sequentially. with 20 rules and 100 events, that's 2000 sequential subprocess calls. i could spawn goroutines and run rules in parallel, probably getting a 10x speedup. i'm starting with sequential because it's simpler to debug.

### metrics + monitoring

no metrics yet. i'm relying on logs and `kubectl` to see what's happening. this will be painful in production. i should add metrics for:
- SQS messages received/processed
- files downloaded and processed
- events processed
- rules evaluated
- detections fired
- errors

### health check endpoints.

i've added basic `/health` and `/ready` endpoints for Kubernetes probes, but they're simple. i should add more sophisticated readiness checks (e.g., can we connect to SQS? is the state database accessible?).

### backfill mode

if i want to run rules against historical CloudTrail logs, there's no good way to do that right now. i'd have to manually trigger SQS messages or use the old S3 polling mode. i should add a backfill mode that can process historical files without re-firing all alerts.

### rule testing framework

i can run `python rule.py < event.json` manually, but there's no automated test suite. i should add pytest tests for each rule with example events.

### graceful shutdown

if Kubernetes sends `SIGTERM`, the pod exits immediately. in-flight rule evaluations might be lost, so `iota` should handle signals properly and finish processing the current batch before exiting.

### rate limiting for slack

if we suddenly have 1000 detections, we'll fire 1000 Slack webhooks as fast as possible. that might hit rate limits or spam the channel. should batch alerts or add rate limiting.

### S3 Select for filtering

CloudTrail files can be large and downloading the entire file just to filter by `eventName` seems wasteful. S3 Select can run SQL queries server-side and return only matching records. Haven't implemented this yet because I wanted to get the basics working first.

### multi-account support

currently, one `iota` instance processes logs from one AWS account. for multi-account setups, i'd need cross-account IAM role assumption or multiple deployments. this is on the roadmap.

### adaptive classifier for multiple log sources

right now `iota` only handles CloudTrail and i want to add support for VPC flow logs, S3 server access logs, ALB logs, and Aurora MySQL audit logs. this requires an adaptive classifier that can automatically detect log types.

## failure modes

### what happens if the pod crashes mid-batch?

the SQS message visibility timeout (5 minutes) will expire, and the message will become [visible again](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html). another pod (or the same pod after restart) will process it. this means we might send duplicate alerts. that's annoying but acceptable (better than missing detections).

the deduplication system helps here: if we process the same event twice, it gets grouped into the same alert instead of creating a duplicate.

### what happens if S3 access breaks (IAM issue, bucket deleted, etc)?

the SQS message processing fails with an AWS error. i log it and the message goes to the [dead letter queue after 3 retries](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-dead-letter-queues.html). if it persists, someone needs to check the logs and fix the IAM role or bucket config.

i should add alerting for "messages in DLQ" but haven't built that yet.

### what happens if SQS is unavailable?

the SQS processor will fail to receive messages. i log the error and retry. if SQS is down for an extended period, messages will queue up in SQS (which has 4 days [retention](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-message-retention.html), 345600 seconds). once SQS is back, we'll process the backlog.

this is actually better than polling! with polling, if the pod is down, we miss files but with SQS, messages wait for us.

### what happens if a rule crashes?

the subprocess returns an error, and i log it and continue to the next rule. one broken rule doesn't stop other rules from running.

the risk is that the broken rule silently stops detecting things. i should add metrics to track "rules failed" vs "rules succeeded" so we notice when rules start failing.

### what happens if the SQLite database gets corrupted?

this really shouldn't happen often (SQLite is pretty robust), but if it does, we'd lose the deduplication state.

recovery: delete the corrupt database, restart the pod. `iota` will continue processing, but we'll lose the ability to deduplicate alerts for a while. new alerts will be sent, but we might get some duplicates until the deduplication state rebuilds.

could mitigate by periodically backing up the SQLite file, but haven't implemented that.

### what happens if Slack is down or the webhook fails?

the alert doesn't get delivered. i log an error. detection still happened, just nobody got notified.

should add retry logic with exponential backoff, but haven't yet. for now, if Slack is down, alerts are lost (but they're in the pod logs).

