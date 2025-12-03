---
title: "iota part 2 - evolution"
date: 2025-12-02T14:21:05Z
draft: false
toc: true
next: true
nomenu: false
notitle: false
---

<figure>
  <img loading="lazy" style="max-height: 70vh;" src="/iotaCharcoal.png" />
  <figcaption>art by <a href="https://faisalkubba.com">fdkubba</a></figcaption>
</figure>

## tl;dr

in the [first post](https://bsssq.xyz/posts/iota-1/), i described the initial design and plan behind `iota`. since then, i've evolved the design and added some more features. i still haven't deployed to production, so this post is also still about design choices and implementation details (rather than production battle-tested results).

## bloom filter

the original design used SQLite for alert deduplication. this was satisfactory for preventing duplicate alerts (if i've already sent an alert for "root login from 1.2.3.4", i don't send it again), but i eventually realized there's another problem i hadn't fully considered.

CloudTrail can write the same event to multiple log files. for example, if you have an organization trail and an account trail, both might contain the same event. additionally, if you have CloudTrail enabled in multiple regions, the same API call might appear in multiple regional logs. when `iota` processed these files, it would run detection rules against the same event multiple times, generating duplicate alerts.

the SQLite alert deduplication did help somewhat, but it was keyed by rule ID and a deduplication string derived from the event. if the same event appeared in different log files, with slightly different metadata (like `sourceIPAddress` or `userAgent`), the deduplication was not able to catch it.

this made me think of `gocloudtrail` and how it uses `EventID` as a natural key. CloudTrail assigns a unique ID to each event, and that ID is consistent across all log files. you can check out `gocloudtrail` [here](https://github.com/deceptiq/gocloudtrail).

### why not SQLite here too?

theoretically, i could add a table like `processed_events (event_id TEXT PRIMARY KEY)`, but that would mean a database write for every single event. even with SQLite's high performance, that's still a lot of I/O. plus, i'd need to query the database for every event to check whether it's been processed. lots of database operations...

a [bloom filter](https://en.wikipedia.org/wiki/Bloom_filter) is perfect for this. it's a probabilistic data structure that can tell you "definitely not seen" or "probably seen" with a configurable false positive rate. memory usage is predictable (~20MB per 10M events = 0.1% false positive rate) and lookups are very fast (~microseconds per check).

the implementation is very straightforward.

```go
type Filter struct {
    mu     sync.RWMutex
    filter *bloom.BloomFilter
    path   string
}

func (f *Filter) Test(data []byte) bool {
    f.mu.RLock()
    defer f.mu.RUnlock()
    return f.filter.Test(data)
}

func (f *Filter) Add(data []byte) {
    f.mu.Lock()
    defer f.mu.Unlock()
    f.filter.Add(data)
}
```

before processing an event, i just check `bloomFilter.Test(eventID)`. if it returns `true`, i skip the event. if `false`, i add it to the filter and process it.

### tradeoff

a 0.1% false positive rate still means 1 in 1000 events might be incorrectly skipped. but false negatives are impossible! if an event is in the filter, it's definitely been processed. for deduplication, false positives are acceptable (we can skip a duplicate) but false negatives would be bad (i.e., we miss a new event). thankfully, the bloom filter helps prevent this. 

because the filter persists to disk, it survives pod restarts. i can configure it with expected capacity (default: 10M events) and false positive rate (default: 0.1%). if i exceed capacity, the false positive rate increases, but within the acceptable margin for deduplication.

## multi-account support

the original design assumed one `iota` instance per AWS account: deploy `iota` in account A, point it at account A's CloudTrail bucket, and it would process logs only from that account. 

well, what if you have multiple AWS (sub)accounts at your org? at least 3: production, staging, development? maybe even a security subaccount? let's say you want centralized detection: one place for all your security rules and where all your alerts can go.

the most straightforward solution to this was to add support for a cross-account IAM role assumption. the idea is: when `iota` runs in one account (i.e., the "central" account), it should also be able to assume IAM roles in other accounts to read their CloudTrail logs.

the implementation here uses a client factory pattern. `iota` needs access to an S3 bucket, so it checks if that bucket has an associated IAM role ARN. if it does, `iota` assumes the role and uses those credentials. if not, it uses the default credentials (IRSA from the pod's `ServiceAccount`).

```go
type ClientFactory struct {
    baseConfig aws.Config
    stsClient  *sts.Client
}

func (f *ClientFactory) GetS3Client(ctx context.Context, roleARN string) (*s3.Client, error) {
    if roleARN == "" {
        return s3.NewFromConfig(f.baseConfig), nil
    }

    result, err := f.stsClient.AssumeRole(ctx, &sts.AssumeRoleInput{
        RoleArn:         aws.String(roleARN),
        RoleSessionName: aws.String("iota-session"),
        DurationSeconds: aws.Int32(3600),
    })
    if err != nil {
        return nil, fmt.Errorf("assume role: %w", err)
    }

    cfg := f.baseConfig.Copy()
    cfg.Credentials = credentials.NewStaticCredentialsProvider(
        aws.ToString(result.Credentials.AccessKeyId),
        aws.ToString(result.Credentials.SecretAccessKey),
        aws.ToString(result.Credentials.SessionToken),
    )

    return s3.NewFromConfig(cfg), nil
}
```

each integration (S3 bucket) can have an associated IAM role ARN stored in the integration database. `iota` assumes the role and uses those credentials to access the S3 logs of the bucket whose logs it's processing.

### setup

each account needs an IAM role that the central account can assume. the role needs permissions to both read CloudTrail logs from S3 and decrypt KMS-encrypted files. the trust policy allows the central account's IAM role to assume it.

you can read more about AWS cross-account documentation [here](https://docs.aws.amazon.com/IAM/latest/UserGuide/tutorial_cross-account-roles.html). the AWS SDK handles credential refresh automatically (so when the assumed role credentials expire after an hour, `iota` can assume the role again).

i do believe centralized detection is simpler than deploying `iota` in every single account. this way, all we have to manage is a single deployment, a single set of rules, and a single alerting configuration. the cross-account IAM role pattern is well-understood and secure, and Terraform can easily handle the IAM setup.

### tradeoff

obviously, more IAM complexity. each account needs an IAM role that the central account can assume, with extra permissions to read CloudTrail logs. the trust policies need to be set up correctly, even if it's easily done with Terraform and is a one-time setup.

## querying the data lake

in part 1, the design had a data lake writer that stored processed events in S3 with hourly partitioning. the structure was: `s3://bucket/log-type/year=2024/month=01/day=15/hour=10/events.json.gz`, which is useful for long-term storage (+ GRC), but i didn't have a way to query it.

using Glue Catalog, i can register the tables and partitions, and using Athena, i can run SQL queries against them. the Glue integration creates tables for each log type, so when the data lake writer flushes a buffer, it can automatically add a Glue partition. 

the table schema is defined per log type (CloudTrail events have different fields than VPC flow logs).

```go
func (c *Catalog) CreateTable(ctx context.Context, logType string) error {
    tableInput := &glue.CreateTableInput{
        DatabaseName: aws.String(c.database),
        TableInput: &glue.TableInput{
            Name: aws.String(logType),
            StorageDescriptor: &glue.StorageDescriptor{
                Location:      aws.String(fmt.Sprintf("s3://%s/%s/", c.bucket, logType)),
                InputFormat:   aws.String("org.apache.hadoop.mapred.TextInputFormat"),
                OutputFormat:  aws.String("org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"),
                SerDeInfo: &glue.SerDeInfo{
                    SerializationLibrary: aws.String("org.openx.data.jsonserde.JsonSerDe"),
                },
                Columns: c.getColumnsForLogType(logType),
            },
            PartitionKeys: []glue.Column{
                {Name: aws.String("year"), Type: aws.String("string")},
                {Name: aws.String("month"), Type: aws.String("string")},
                {Name: aws.String("day"), Type: aws.String("string")},
                {Name: aws.String("hour"), Type: aws.String("string")},
            },
        },
    }
    // ... create table
}
```

the partition keys here match the S3 prefix structure. so when querying with Athena, you can filter by partition to reduce data scanned:

```sql
SELECT eventName, COUNT(*) as count
FROM cloudtrail_events
WHERE year = '2025' AND month = '01' AND day = '15'
GROUP BY eventName
ORDER BY count DESC
```

Athena only scans the partitions that match the `WHERE` clause, which reduces expensive operations and boosts performance.

the data lake is only really useful if we can query it. Glue + Athena are the standard AWS way to query S3 data, and now `iota` can both detect events in real-time and provide historical querying capability. we can use this to run ad-hoc queries, build dashboards, or do compliance reporting.

### tradeoff

simply put: more AWS services to manage. Glue, Athena, S3. however, these are serverless and only cost when used. the integration is optional, i.e., if you don't configure a Glue database, the data lake writer still works (just without querying capability). you can add Glue later on without changing the data format.

the AWS SDK requires a lot of boilerplate to create tables and partitions. the `CreateTable` call has many required fields, and the schema definition is highly verbose. once it's set up, though, it works reliably, so the automatic partition management is worth the complexity.

## observability

production monitoring still needs metrics...so i had to build the metrics endpoint. logs are useful for debugging, but metrics can let us see trends, set up better alerting, and understand the system's behaviour over time. i used Promethues here, and added some counters and histograms for key operations:

- events processed (by log type, status)
- rules evaluated (by rule ID, result)
- alerts generated (by severity, rule ID)
- alerts forwarded (by output type, status)
- SQS messages processed
- S3 objects downloaded (count and bytes)
- data lake writes (count and bytes)
- processing errors (by component, error type)

the metrics are exposed at `/metrics` when `ENABLE_METRICS=true` is set. the implementation uses the Prometheus Go client library:

```go
var EventsProcessedTotal = promauto.NewCounterVec(
    prometheus.CounterOpts{
        Name: "iota_events_processed_total",
        Help: "Total number of events processed",
    },
    []string{"log_type", "status"},
)

func RecordEventProcessed(logType, status string, duration time.Duration) {
    EventsProcessedTotal.WithLabelValues(logType, status).Inc()
    EventsProcessedDuration.WithLabelValues(logType).Observe(duration.Seconds())
}
```

i instrumented the key code paths to record metrics. whenever an event is processed, i just increment the counter. when a rule is evaluated, i record the result. when an alert is generated, i track the severity and rule ID.

even without production deployment, having metrics helps me understand system behaviour during testing. i can see how many events are processed, which rules fire most often, and where errors occur. 

### tradeoff

more code to maintain. i need to instrument every code path that matters, but the Prometheus client library doesn't make this very straightforward. 

i also enhanced the health check endpoints. the original just had basic `/health` and `/ready` endpoints that just returned `200 OK`. i added a readiness checker interface so the `/ready` endpoint can actually verify the system is ready.

```go
type ReadinessChecker interface {
    Check(ctx context.Context) error
}

func (s *HealthServer) readyHandler(w http.ResponseWriter, r *http.Request) {
    if s.readiness != nil {
        ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
        defer cancel()

        if err := s.readiness.Check(ctx); err != nil {
            w.WriteHeader(http.StatusServiceUnavailable)
            _, _ = w.Write([]byte(fmt.Sprintf("NOT READY: %v", err)))
            return
        }
    }

    w.WriteHeader(http.StatusOK)
    _, _ = w.Write([]byte("READY"))
}
```

k8s readiness probes should actually check if the service is ready, not just if the HTTP server is running. if the SQLite database is corrupted, or SQS is unreachable, the pod should report "not ready" so k8s doesn't send traffic to it.

## parallel processing

the original design processed files sequentially, but now, when an SQS message arrives, `iota` downloads the S3 object, processes it, runs rules, and sends alerts. then it moves to the next message.

this works fine for low-volume scenarios. but if CloudTrail writes 100 log files at once (maybe during a busy period or after a backlog), processing them sequentially takes a long time. the SQS visibility timeout is 5 minutes, so if processing takes longer than that, messages might become visible again and get reprocessed.

i added configurable worker pools for parallel S3 downloads and log processing:

```go
downloadWorkers := flag.Int("download-workers", 5, "number of parallel download workers")
processWorkers  := flag.Int("process-workers", 10, "number of parallel process workers")
```

the SQS handler receives messages and dispatches them to worker pools, the download workers fetch S3 objects in parallel, and the process workers parse logs and run rules in parallel. this improves throughput when processing large batches of files.

if i receive 100 SQS messages at once, i can download and process them in parallel instead of sequentialy, thereby reducing total processing time and making better use of the available CPU/network bandwidth.

### tradeoff

more complexity. i need to manage worker pools, handle errors from multiple goroutines, and ensure thread-safety for shared state (bloom filter, state database), but Go's concurrency primitives make this manageable. channels for communication, mutexes for shared state, and context for cancellation.

the default worker counts (5 download, 10 process) are conservative, but you can increase them if you have more CPU or network bandwidth. however, too many workers can overwhelm the system or hit AWS API rate limits.

i also added state tracking per bucket/account/region. the original design used SQLite for alert deduplication, so i added a separate table to track the last processed S3 key per bucket, account, and region:

```sql
CREATE TABLE processed_keys (
    bucket TEXT NOT NULL,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    last_key TEXT NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (bucket, account_id, region)
);
```

if the pod restarts, it can skip already-processed files. this is separate from alert deduplication. state tracking prevents reprocessing files and alert deduplication prevents duplicate alerts for the same event.

## multiple log sources

the original design only handled CloudTrail, but security detections need multiple log sources. a single CloudTrail event might not be suspicious, but combined with VPC flow logs showing unusual network traffic, it could be. also, having multiple log sources in one system makes correlation easier.

i added parsers and rules for:
- S3 Server Access Logs (3 rules: insecure access, unauthenticated access, access errors)
- VPC Flow Logs (3 rules: inbound traffic port blocklist, SSH allowed, unapproved outbound DNS)
- ALB Access Logs (2 rules: suspicious user agent, high error rate)

the parsers use the same adaptive classifier pattern as CloudTrail. rules follow the same Python interface. this extends `iota` beyond just CloudTrail detection.

### tradeoff

more complexity...again. each log type has a different format, and the parsers need to handle different structures. rules need to handle different event shapes, and the adaptive classifer isn't fully integrated yet (the parsers exist, but the processor still uses a simple map-based classifer for CloudTrail). TODO: automatically detect log types.

## deployment tooling

i added:

- GitHub Actions workflow for CI (tests, linting, Docker builds)
- GitHub Actions workflow for releases (multi-arch Docker images pushed to Docker Hub)
- a `Makefile` with common tasks
- `.dockerignore` for optimized builds
- kubernetes deployment manifests with proper health checks and resource limits

deployment should be easy. the workflows handle building Docker images, running tests, and pushing to registries, and the Makefile provides a consistent interface for common tasks. the kubernetes manifests are production-ready with proper health checks and resource limits.

## next

1. deploy to a test cluster
2. set up SNS/SQS via Terraform
3. point to org CloudTrail bucket
4. watch metrics + logs
5. validate detection rules with live CloudTrail data