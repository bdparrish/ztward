# Route 53 Subdomain & ALB Alias Guide

This guide explains how to create public subdomains for your domain (`example.com` below) in Route 53 and point them at the AWS Load Balancers that front the EKS ingress resources. Follow it whenever we add or rotate external endpoints (for example `auth.example.com`, `grpc.example.com`, `ui.example.com`, and `api.example.com`).

## Prerequisites

- AWS CLI configured with permissions for Route 53 (list/change hosted zones and record sets).
- Access to the EKS cluster so you can read the ingress resources (`kubectl get ingress -n ztward`).
- The ACM certificate already issued in the same region as the ALBs (attached via Helm values).

## 1. Identify the Correct Hosted Zone

List zones and capture the ID that manages `example.com`:

```bash
aws route53 list-hosted-zones-by-name \
  --dns-name example.com \
  --max-items 1 \
  --query "HostedZones[0].Id" \
  --output text
```

Example result: `/hostedzone/Z05839483O3776RN6IU18`. Strip the `/hostedzone/` prefix when you pass it to other commands.

Validate that the zone already contains the base NS/SOA records and note any existing `A`/`AAAA` entries:

```bash
aws route53 list-resource-record-sets \
  --hosted-zone-id Z05839483O3776RN6IU18
```

## 2. Gather ALB Hostnames and Zone IDs

Each ingress creates its own ALB. Use `kubectl` to map service ↔ hostname:

```bash
kubectl get ingress -n ztward
```

Example output (truncated):

| Ingress             | Host                       | ALB DNS Name                                                                |
| ------------------- | ------------------------- | --------------------------------------------------------------------------- |
| `ztward-keycloak` | `auth.example.com`   | `<keycloak-alb-hostname>`    |
| `ztward-envoy`    | `grpc.example.com`   | `<envoy-alb-hostname>`    |
| `ztward-pap`      | `api.example.com`    | `<pap-alb-hostname>`   |
| `ztward-pap-ui`   | `ui.example.com`     | `<pap-ui-alb-hostname>`   |

You also need the hosted-zone ID that Amazon assigns to ALBs in the cluster’s region. For Application Load Balancers in `us-east-2`, the ID is `Z3AADJGX6KTTL2` (see the [AWS reference](https://docs.aws.amazon.com/general/latest/gr/elb.html#elb-listings) if you deploy elsewhere).

## 3. Author Change Batches

Route 53 records are updated via change batches. Use `UPSERT` so re-running the command is idempotent. Below is a template for `auth.example.com`; create similar files for `grpc`, `ui`, and `api` by swapping the host/ALB values.

```json
{
  "Comment": "Point auth.example.com at the Keycloak ALB",
  "Changes": [
    {
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "auth.example.com.",
        "Type": "A",
        "AliasTarget": {
          "HostedZoneId": "Z3AADJGX6KTTL2",
          "DNSName": "<keycloak-alb-hostname>.",
          "EvaluateTargetHealth": false
        }
      }
    }
  ]
}
```

Why aliases? They let Route 53 “expose” the ALB’s public IPs without hard-coding them, and they automatically track any IP rotations performed by AWS.

## 4. Apply the UPSERTs

Run the change for each host:

```bash
aws route53 change-resource-record-sets \
  --hosted-zone-id Z05839483O3776RN6IU18 \
  --change-batch file://auth-alias.json
```

Capture the `ChangeInfo.Id` if you want to wait for propagation:

```bash
aws route53 get-change --id <change-id>
```

Status transitions from `PENDING` to `INSYNC` once Route 53 has pushed the update globally.

## 5. Validate DNS and TLS

After the changes report `INSYNC`, confirm each host resolves to the ALB by checking the returned IPs:

```bash
dig +short auth.example.com
dig +short grpc.example.com
dig +short ui.example.com
dig +short api.example.com
```

Then verify HTTPS/TLS is active and the ACM certificate matches:

```bash
curl -I https://auth.example.com
curl -I https://ui.example.com
```

Expect `HTTP/2 200` (or 301 redirect) and the certificate CN/SAN covering the hostnames you requested in ACM.

## 6. Troubleshooting

- **`curl: (6) Could not resolve host`** – The record either lives in a different hosted zone or has not been created. Re-run `list-resource-record-sets` to confirm the name, and ensure your domain registrar delegates to the Route 53 NS set shown in the zone.
- **Alias points to the wrong ALB** – Update the `DNSName` in the change batch with the new value from `kubectl get ingress`, then re-run the UPSERT.
- **Certificate mismatch** – Confirm Helm’s ingress annotations reference the current ACM ARN and that the certificate includes every hostname (or use a wildcard like `*.example.com`).

Once DNS is healthy, no further action is required—future ALB IP rotations happen transparently through the alias records.
