# AWS deployment example

Two CloudFormation templates that run one Winnie the Agent sensor on one EC2 host, with its
events shipped one way to a bucket in another account. Use them as a starting point; read
them before deploying, and run the checks below after every change.

| File | Deploy in | Creates |
|---|---|---|
| `events-bucket.yaml` | a separate account (for example your security or log archive account), in the sensor's region | the events bucket and its policy |
| `sensor.yaml` | a dedicated account for the sensor | VPC, endpoints, ECR repository, instance role, log groups, optional trail, launch template, instance, Elastic IP |
| `check.py` | nowhere: run locally | offline checks of both templates (`tests/test_deploy_aws.py` runs them too) |

## What gets created

- **Network.** One VPC, one public subnet, an internet gateway and no NAT. The route to
  the internet gateway exists only so replies to inbound connections leave; the instance
  security group allows outbound traffic only on 443 to the S3 prefix list and to six
  interface endpoints (SSM, SSM messages, EC2 messages, ECR API, ECR registry, CloudWatch
  Logs). The S3 gateway endpoint policy allows `PutObject` to the events prefix and reads
  from the Amazon Linux package, ECR layer and SSM agent buckets only. VPC flow logs go to
  CloudWatch Logs (`FlowLogsEnabled`).
- **Inbound.** One security group rule per public port, each from `InboundCidr` only, each
  present only with `InboundEnabled=true` and only when the scenario runs that service.
  The `ScenarioServices` mapping in `sensor.yaml` lists each scenario's services;
  `tests/test_deploy_aws.py` keeps it equal to the scenarios. Public ports: SSH 22, FTP 21
  and 30000-30019, Telnet 23, SMTP 25 (only with `SmtpEnabled=true`), HTTP 80, MSSQL 1433,
  MySQL 3306, SIP 5060 UDP and TCP, PostgreSQL 5432, Redis 6379, HL7 MLLP 2575, and the S3
  trap on `S3Port` (default 9000).
- **Host.** Amazon Linux 2023, IMDSv2 required with a hop limit of 1, no key pair; the
  host's own sshd is masked so port 22 is the fake SSH service and administration is SSM
  Session Manager only. The bootstrap installs Docker, turns the userland proxy off,
  writes the compose files and two config files from the image's template, and runs the
  stack as a systemd unit.
- **Containment on the host.** `DOCKER-USER` rules drop traffic from every bridged
  container to 169.254.169.254 and drop every new connection from the front-end
  (172.30.0.0/24) and agents (172.30.1.0/24) networks; only replies pass.
- **Exporter.** A fifth container runs `python -m agents ship` every five minutes on the
  host network. It is the only container that can use the instance role, which may pull
  this one image, write this one log group and `s3:PutObject` under the events prefix.
  It has its own `config-ship.ini` with `[connector.s3_events]` on (`passwords = hash`,
  `bucket_owner` sent as `ExpectedBucketOwner`); the shared `config.ini` keeps the export
  off, because `run-all` in the agents container would otherwise try to ship without
  credentials or egress.
- **Bucket.** Versioned, encrypted, public access blocked, lifecycle expiry. Its policy
  lets the sensor role (matched by ARN) put under the events prefix and denies everything
  else to every principal in the sensor account, so nothing there can read, list or
  delete. Requests without TLS are denied. With `TrailEnabled=true` in both stacks, the
  sensor account's own multi-region trail delivers under `cloudtrail/`.

No model calls: the host has no route to a model API, so `[listeners] llm = false`, the
SSH persona gives canned replies and triage is deterministic.

### Cost

Roughly 70 to 90 USD a month in a typical region on demand, most of it the six interface
endpoints. A `t3.small`, its volume and the Elastic IP add up to roughly 20 USD; S3, logs,
flow logs and the first trail's management events are usually a few dollars, but log
ingestion grows with attack traffic. Watch the host and flow log groups during the first
weeks. Check current prices for your region; these are orders of magnitude, not a quote.

## Facts learned from deploying it

- **Docker Compose on Amazon Linux 2023.** AL2023 does not package the Docker Compose
  plugin, and a host without an internet route cannot download it. The bootstrap copies
  the binary out of a copy of the `docker/compose-bin` image pushed to the stack's own ECR
  repository (`ComposeImageTag`). The repository's lifecycle rule expires untagged images
  only, so that copy never expires; keep it that way if you change the rule.
- **Real client addresses.** Docker's userland proxy rewrites every source address to the
  bridge gateway. The bootstrap sets `"userland-proxy": false`, so events, per-source
  limits and blocklists see the real client.
- **No default for `InboundCidr`.** CloudFormation rejects a parameter default that fails
  the parameter's own `AllowedPattern`, and an open default would expose the host by
  accident. Every deploy passes the range explicitly.
- **First launch in a new account.** A new AWS account's first EC2 launch can be held
  briefly for account validation. Deploy with `HostEnabled=false` first; the network,
  repository and role do not wait for it, and the image can be pushed meanwhile.
- **SMTP is off by default.** An open-looking mail service draws abuse reports against
  the sensor's address. To run it in a scenario that has SMTP (`sip-provider`, `saas`),
  redeploy with `SmtpEnabled=true`: it opens port 25 and stops setting
  `[listeners] smtp_enabled = false` in the generated config.

## Deploy

Every stack change is created as a change set, reviewed, then executed. Replace the
placeholders; `B` is the bucket account's profile and `S` the sensor account's.

```bash
B="--profile <bucket-account-profile> --region us-east-1"
S="--profile <sensor-account-profile> --region us-east-1"
```

### 1. Local checks

```bash
uv run python deploy/aws/check.py                 # prints ok
uv run pytest tests/test_deploy_aws.py
uvx cfn-lint deploy/aws/sensor.yaml deploy/aws/events-bucket.yaml   # optional
```

### 2. Events bucket (bucket account)

```bash
aws cloudformation deploy --stack-name winnie-events \
  --template-file deploy/aws/events-bucket.yaml $B \
  --parameter-overrides BucketName=example-winnie-events SensorAccountId=<sensor account id> \
    SensorRoleName=winnie-sensor-host TrailEnabled=false \
  --no-execute-changeset
aws cloudformation describe-change-set --change-set-name <change set arn> $B \
  --query "Changes[].ResourceChange.{Action:Action,Id:LogicalResourceId,Type:ResourceType}" --output table
aws cloudformation execute-change-set --change-set-name <change set arn> $B
aws cloudformation wait stack-create-complete --stack-name winnie-events $B
```

Expect two `Add` changes: the bucket and its policy. Deploy the bucket in the same region
as the sensor: the sensor reaches S3 only through its gateway endpoint, which serves its
own region. Never deploy this stack in the sensor account: its deny statements cover every
principal of that account.

### 3. Sensor network, repository and role (host off)

```bash
aws ec2 describe-managed-prefix-lists $S \
  --filters Name=prefix-list-name,Values=com.amazonaws.us-east-1.s3 --query "PrefixLists[0].PrefixListId"
aws cloudformation deploy --stack-name winnie-sensor \
  --template-file deploy/aws/sensor.yaml --capabilities CAPABILITY_NAMED_IAM $S \
  --parameter-overrides InboundCidr=<your address>/32 HostEnabled=false \
    Scenario=sip-provider S3PrefixListId=<pl-...> \
    EventsBucketName=example-winnie-events EventsBucketOwner=<bucket account id> \
  --no-execute-changeset
aws cloudformation describe-change-set --change-set-name <change set arn> $S \
  --query "Changes[].ResourceChange.{Action:Action,Id:LogicalResourceId,Type:ResourceType}" --output table
aws cloudformation execute-change-set --change-set-name <change set arn> $S
aws cloudformation describe-stacks --stack-name winnie-sensor $S --query "Stacks[0].Outputs"
```

Expect only `Add` actions and no `LaunchTemplate`, `Instance` or `EipAssociation` (host
off). For the optional trail, first redeploy the bucket stack with `TrailEnabled=true`
(and `TrailName=<NamePrefix>-trail`), then pass `TrailEnabled=true` here.

### 4. Images

From the repository root, for `linux/amd64` (the AMI is x86_64):

```bash
R=<RepositoryUri output>
aws ecr get-login-password $S | docker login --username AWS --password-stdin "${R%%/*}"
docker buildx build --platform linux/amd64 -t "$R:<git sha>" --push .
docker pull --platform linux/amd64 docker/compose-bin:<compose version>
docker tag docker/compose-bin:<compose version> "$R:compose-bin"
docker push "$R:compose-bin"
aws ecr describe-image-scan-findings --repository-name winnie-sensor --image-id imageTag=<git sha> $S
```

Tags are immutable. A newer Compose binary goes under a new tag, passed as
`ComposeImageTag`.

### 5. Turn the host on

Repeat step 3 with `HostEnabled=true ImageTag=<git sha>` and the same other values, as its
own reviewed change set. Expect `LaunchTemplate`, `Instance` and `EipAssociation` to be
added. Keep `InboundCidr` at your own address until the checklist below passes.

## Containment checklist

Open a shell with `aws ssm start-session --target <InstanceId> $S`, then `sudo -i` and
`cd /opt/sensor`.

- [ ] `tail /var/log/sensor-bootstrap.log` ends with `bootstrap complete`; `docker compose
      ps` shows ssh, listeners, agents and exporter running; `systemctl is-enabled sshd`
      prints `masked`.
- [ ] `iptables -S DOCKER-USER` shows the two 169.254.169.254 drops and the two
      `! --ctstate RELATED,ESTABLISHED` drops.
- [ ] Containers cannot connect out. Each command must time out (not be refused, not
      answer):

      for s in listeners agents; do
        docker compose exec -T $s python -c "import socket; socket.create_connection(('192.0.2.1', 443), timeout=5)"
        docker compose exec -T $s python -c "import urllib.request; urllib.request.urlopen('https://s3.amazonaws.com', timeout=5)"
      done

- [ ] Containers cannot reach the metadata service (each times out; the exporter, on the
      host network, can reach it by design):

      for s in listeners agents; do
        docker compose exec -T $s python -c "import urllib.request as u; u.urlopen(u.Request('http://169.254.169.254/latest/api/token', method='PUT', headers={'X-aws-ec2-metadata-token-ttl-seconds': '60'}), timeout=5)"
      done

- [ ] The role can put and cannot get, list or delete (on the host, which uses the role):

      B=example-winnie-events
      echo verify | aws s3 cp - s3://$B/events/verify/$(date +%s).txt       # succeeds
      aws s3 ls s3://$B/events/                                             # AccessDenied
      aws s3api get-object --bucket $B --key events/verify/<key> /dev/null  # AccessDenied
      aws s3api delete-object --bucket $B --key events/verify/<key>         # AccessDenied
      echo verify | aws s3 cp - s3://$B/other/verify.txt                    # AccessDenied

- [ ] Events show real client addresses: connect from your own address (for example
      `nc -vz <PublicIp> 22`) and check that `docker compose logs listeners ssh` or the
      host log group shows that address, not 172.30.0.1.
- [ ] An exported object appears: within about five minutes of that connection, from the
      bucket account, `aws s3 ls s3://example-winnie-events/events/ --recursive $B | tail`
      lists a new object.

Only then widen `InboundCidr` (to `0.0.0.0/0` for an internet-facing sensor) in a new
reviewed change set.

## Stop and rollback

- **Fast stop:** redeploy with `InboundEnabled=false`. Every inbound rule is removed; the
  host keeps running and shipping. Without waiting for a change set: `aws ec2
  stop-instances --instance-ids <InstanceId> $S` (`start-instances` resumes; the systemd
  units start the stack again).
- **Host off, network kept:** redeploy with `HostEnabled=false`.
- **Remove the sensor:** `aws cloudformation delete-stack --stack-name winnie-sensor $S`.
  The ECR repository is retained on purpose; delete it by hand when done. The bucket stack
  is not touched, and the bucket itself is retained even if its stack is deleted.

## Limits

- One host in one Availability Zone of one region. Replacing the instance starts the event
  log, the export cursor and the per-source state from zero; events already exported are
  kept in the bucket.
- The events bucket must be in the sensor's region.
- No TLS anywhere on the sensor: the HTTP and S3 traps speak plain HTTP, so publishing
  them on 443 is pointless.
- No model calls: adding a model provider means an egress path (for Bedrock, a
  `bedrock-runtime` interface endpoint and an `InvokeModel` grant) and a review of what
  the front-ends may then reach.
