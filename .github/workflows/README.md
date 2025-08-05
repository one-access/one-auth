# GitHub Actions Workflows

Automated CI/CD workflows for OneAuth application.

## Workflows

### `one-auth-pr.yml` - Pull Request Validation

**Trigger**: Pull requests to `master/main`  
**Purpose**: Build verification and quality checks

- ✅ Java 17 + Maven build
- ✅ Docker image creation
- ✅ Automated PR status comments
- ⚡ Maven dependency caching

### `one-auth-main.yml` - Build & Deploy

**Trigger**: Push to `master/main` + manual dispatch  
**Purpose**: Production image builds and registry push

- 🏗️ Application build (tests skipped)
- 🐳 Docker image with `latest` tag
- 🚀 Push to Google Artifact Registry
- 💤 AWS ECR support (commented out)

## Required Repository Setup

### GitHub Variables

Configure in **Settings > Secrets and Variables > Actions > Variables**:

#### Active (GCP)

```ini
GCP_REGION = us-central1
GCP_WIF_PROVIDER = projects/123456/locations/global/workloadIdentityPools/github-actions-v3/providers/github-actions-v3
GCP_SERVICE_ACCOUNT = github-actions@oneaccess-pride.iam.gserviceaccount.com
GAR_REGISTRY = us-central1-docker.pkg.dev/oneaccess-pride/oneaccess-registry
```

#### Future AWS Support

```sh
AWS_REGION = us-east-1
AWS_ROLE_ARN = arn:aws:iam::ACCOUNT:role/oneaccess-github-actions
ECR_REGISTRY = ACCOUNT.dkr.ecr.REGION.amazonaws.com/oneaccess-registry
```

## Security

- 🔐 **No secrets required** - uses OIDC/Workload Identity Federation
- 🎯 **Minimal permissions** - read-only for PRs, id-token for deploys
- 🔒 **Keyless authentication** - no service account keys stored

## Usage

### Development Workflow

1. **Create PR** → automatic build verification
2. **Review & merge** → production image build
3. **Image ready** at `one-auth:latest` in registry

### Manual Deployment

1. Go to **Actions** tab
2. Select "Build & Push Image"
3. Click **Run workflow**

## Registry Management

- **Minimal tags**: Only `latest` to conserve registry space
- **GCP ready**: Active push to Google Artifact Registry
- **AWS ready**: Uncomment AWS section when needed

## Enable AWS ECR

1. Uncomment AWS section in `one-auth-main.yml` (lines 72-85)
2. Set AWS repository variables above
3. Can use either GCP and AWS to push image. Or use both (not ideal though)