# AWS Demo Environment

This folder contains infrastructure-as-code assets for standing up a Ztward
demo environment in a public AWS account.  The Terraform definitions create:

- A dedicated VPC with public and private subnets across two AZs
- An Amazon EKS cluster with control-plane logging enabled
- One managed node group using `c6g.xlarge` (Graviton2) instances
- IAM roles and policies required for:
  - Worker nodes
  - The AWS Load Balancer Controller (ingress)
  - The EBS CSI driver (persistent volumes)

> **Important:** The templates follow best practices for a demo scale cluster but
> they will still create billable AWS resources (VPC endpoints, NAT gateways,
> EC2 instances, etc.).  Review all files before running Terraform.

## Directory Layout

```
deployment/aws/
├── README.md                # This guide
└── terraform/               # Terraform project
    ├── locals.tf            # Common tags
    ├── main.tf              # Providers
    ├── variables.tf         # Input variables with defaults
    ├── vpc.tf               # VPC + subnets + routing
    ├── eks.tf               # EKS control plane, nodegroup, IAM add-ons
    ├── outputs.tf           # Useful outputs after apply
    └── terraform.tfvars     # (Optional) user overrides
```

## Usage (Green Deployment Runbook)

1. **Provision / Reset the cluster**
   ```bash
   cd deployment/aws/terraform
   terraform destroy      # optional but recommended when starting fresh
   terraform init
   terraform apply
   cd ../../..
   ```

2. **Configure kubectl for the new cluster**
   ```bash
   aws eks update-kubeconfig --name ztward-demo --region us-east-2
   ```

3. **Populate AWS Secrets Manager with the Ztward secrets**
   ```bash
   deployment/helm/write-aws-secrets.sh
   ```

4. **(For older clusters only)** Sync AWS secrets into Kubernetes*  
   Terraform now installs the External Secrets operator and `ClusterSecretStore`,
   so this helper should only be used when debugging legacy clusters:
   ```bash
   deployment/helm/sync-aws-secrets.sh
   ```

5. **Create the ECR pull secret (12‑hour token)**
   ```bash
   deployment/aws/ecr/create-ecr-secret.sh
   ```

6. **Align database passwords with Keycloak / Ztward users**
   ```bash
   export POSTGRESQL_PASSWORD=$(kubectl get secret ztward-postgresql-secret -n ztward -o jsonpath='{.data.password}' | base64 --decode)
   kubectl exec -n ztward statefulset/ztward-postgresql -- \
     psql -U keycloak -d keycloak -c "ALTER USER keycloak WITH PASSWORD '${POSTGRESQL_PASSWORD}';"

   export ZTWARD_DATABASE_PASSWORD=$(kubectl get secret ztward-ztward-secret -n ztward -o jsonpath='{.data.database-password}' | base64 --decode)
   kubectl exec -n ztward statefulset/ztward-postgresql -- \
     psql -U keycloak -d keycloak -c "ALTER USER ztward WITH PASSWORD '${ZTWARD_DATABASE_PASSWORD}';"
   ```

7. **Watch ingress health and publish DNS aliases**
   ```bash
   kubectl get ingress -n ztward -w
   # wait for ADDRESS columns to populate, then in another shell:
   deployment/aws/dns/update-ingress-aliases.sh <your-route53-hosted-zone-id>
   dig auth.example.com
   curl https://auth.example.com
   ```

8. **Bounce the public-facing workloads once secrets / DNS are in place**
   ```bash
   kubectl rollout restart \
     deployment/ztward-keycloak \
     deployment/ztward-key-access \
     deployment/ztward-key-manager \
     deployment/ztward-platform \
     deployment/ztward-pap \
     deployment/ztward-pap-ui \
     -n ztward
   ```

\*If you never rely on the legacy sync script, feel free to skip step 4 entirely. External Secrets handles ongoing reconciliation automatically once `write-aws-secrets.sh` has populated AWS Secrets Manager.

## Clean Up

Delete the environment via:

```bash
cd deployment/aws/terraform
terraform destroy
```

This removes the VPC, cluster, nodegroups, IAM roles, and gateways created by
the project.  After `destroy` completes you can manually remove any Route 53
records or additional resources you added on top of the demo cluster.
