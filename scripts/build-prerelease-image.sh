#!/usr/bin/env bash
set -euo pipefail

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Build a local prerelease image or publish an unsigned test image to Amazon ECR.

Usage:
  scripts/build-prerelease-image.sh local [--repository REPOSITORY] [--tag TAG]
  scripts/build-prerelease-image.sh push  [--ecr-repository NAME] [--profile PROFILE]
                                           [--region REGION] [--tag TAG]

Modes:
  local  Build the Dockerfile production target for the current host platform
         and load it into the local Docker image store.
  push   Build and push linux/amd64 and linux/arm64 to an existing ECR
         repository with SBOM and maximum provenance attestations.

Defaults:
  local repository: traversal-connector
  ECR repository:   traversal-connector
  tag:              prerelease-<current-short-git-sha>

For push, the AWS account comes from the active credentials. Region precedence
is --region, AWS_REGION, AWS_DEFAULT_REGION, then the AWS CLI configuration.
TAG must start with "prerelease-" and contain only letters, digits, periods,
underscores, and hyphens. This command never creates release tags or assets.
EOF
}

[[ $# -gt 0 ]] || {
  usage >&2
  exit 1
}

mode=$1
shift
case "$mode" in
  local | push) ;;
  -h | --help)
    usage
    exit 0
    ;;
  *) die "mode must be 'local' or 'push'" ;;
esac

repository=
ecr_repository=traversal-connector
profile=
region=
tag=
while [[ $# -gt 0 ]]; do
  case "$1" in
    --repository)
      [[ "$mode" == local ]] || die "--repository is only valid in local mode; use --ecr-repository for push"
      [[ $# -ge 2 ]] || die "--repository requires a value"
      repository=$2
      shift 2
      ;;
    --ecr-repository)
      [[ "$mode" == push ]] || die "--ecr-repository is only valid in push mode"
      [[ $# -ge 2 ]] || die "--ecr-repository requires a value"
      ecr_repository=$2
      shift 2
      ;;
    --profile)
      [[ "$mode" == push ]] || die "--profile is only valid in push mode"
      [[ $# -ge 2 ]] || die "--profile requires a value"
      profile=$2
      shift 2
      ;;
    --region)
      [[ "$mode" == push ]] || die "--region is only valid in push mode"
      [[ $# -ge 2 ]] || die "--region requires a value"
      region=$2
      shift 2
      ;;
    --tag)
      [[ $# -ge 2 ]] || die "--tag requires a value"
      tag=$2
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *) die "unknown argument: $1" ;;
  esac
done

command -v git >/dev/null 2>&1 || die "git is required"
[[ -z $(git status --porcelain) ]] || die "working tree is dirty; commit or stash changes first"

short_sha=$(git rev-parse --short HEAD)
repository=${repository:-traversal-connector}
tag=${tag:-prerelease-${short_sha}}

[[ "$tag" =~ ^prerelease-[A-Za-z0-9][A-Za-z0-9._-]*$ ]] ||
  die "tag must use the safe prerelease syntax prerelease-<name>: $tag"

command -v docker >/dev/null 2>&1 || die "docker is required"
docker buildx version >/dev/null 2>&1 || die "docker buildx is required"
docker info >/dev/null 2>&1 || die "Docker daemon is unavailable"

if [[ "$mode" == local ]]; then
  [[ -n "$repository" && "$repository" != *[[:space:]]* ]] ||
    die "repository must be non-empty and contain no whitespace"
  image_ref="${repository}:${tag}"
  docker buildx build \
    --target production \
    --load \
    --tag "$image_ref" \
    .
  printf 'Loaded local prerelease image: %s\n' "$image_ref"
  exit 0
fi

command -v aws >/dev/null 2>&1 || die "aws is required for push mode"
[[ ${#ecr_repository} -ge 2 && ${#ecr_repository} -le 256 ]] ||
  die "ECR repository name must be between 2 and 256 characters"
[[ "$ecr_repository" =~ ^[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)*$ ]] ||
  die "invalid ECR repository name: $ecr_repository"

if [[ -z "$region" ]]; then
  region=${AWS_REGION:-${AWS_DEFAULT_REGION:-}}
fi
if [[ -z "$region" ]]; then
  if [[ -n "$profile" ]]; then
    region=$(aws configure get region --profile "$profile" 2>/dev/null || true)
  else
    region=$(aws configure get region 2>/dev/null || true)
  fi
fi
[[ -n "$region" ]] || die "AWS region is unresolved; pass --region or configure AWS_REGION/AWS_DEFAULT_REGION"
[[ "$region" =~ ^[a-z]{2}(-[a-z0-9]+)+-[0-9]+$ ]] || die "invalid AWS region: $region"

aws_args=(--region "$region")
if [[ -n "$profile" ]]; then
  aws_args=(--profile "$profile" "${aws_args[@]}")
fi

identity_error=$(mktemp)
if identity=$(aws sts get-caller-identity "${aws_args[@]}" \
  --query '[Account,Arn]' --output text 2>"$identity_error"); then
  read -r account arn <<<"$identity"
else
  identity_status=$?
  cat "$identity_error" >&2
  rm -f "$identity_error"
  die "could not resolve AWS caller identity (aws exit $identity_status)"
fi
rm -f "$identity_error"
[[ "$account" =~ ^[0-9]{12}$ ]] || die "AWS caller account must be exactly 12 digits"

partition=${arn#arn:}
partition=${partition%%:*}
case "$partition" in
  aws | aws-us-gov) dns_suffix=amazonaws.com ;;
  aws-cn) dns_suffix=amazonaws.com.cn ;;
  *) die "unsupported AWS partition in caller ARN: $partition" ;;
esac

registry="${account}.dkr.ecr.${region}.${dns_suffix}"
image_ref="${registry}/${ecr_repository}:${tag}"
describe_error=$(mktemp)
metadata=$(mktemp)
trap 'rm -f "$describe_error" "$metadata"' EXIT

if aws ecr describe-images "${aws_args[@]}" \
  --repository-name "$ecr_repository" \
  --image-ids "imageTag=$tag" >/dev/null 2>"$describe_error"; then
  die "ECR tag already exists; refusing to overwrite: $image_ref"
else
  describe_status=$?
fi

if ! grep -Fq 'ImageNotFoundException' "$describe_error"; then
  cat "$describe_error" >&2
  if grep -Fq 'RepositoryNotFoundException' "$describe_error"; then
    die "ECR repository does not exist and must be created before publishing: $ecr_repository"
  fi
  die "could not establish that ECR tag is absent (aws exit $describe_status): $image_ref"
fi

if ! aws ecr get-login-password "${aws_args[@]}" |
  docker login --username AWS --password-stdin "$registry"; then
  die "ECR Docker login failed"
fi

docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --target production \
  --sbom=true \
  --provenance=mode=max \
  --push \
  --tag "$image_ref" \
  --metadata-file "$metadata" \
  .

digest=$(sed -nE 's/.*"containerimage\.digest"[[:space:]]*:[[:space:]]*"(sha256:[0-9a-f]{64})".*/\1/p' "$metadata" | head -n 1)
[[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || die "push succeeded but Buildx did not report an image digest"
printf 'Published unsigned prerelease image: %s/%s@%s\n' "$registry" "$ecr_repository" "$digest"
