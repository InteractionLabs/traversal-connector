#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
builder="$repo_root/scripts/build-prerelease-image.sh"
temp=$(mktemp -d)
trap 'rm -rf "$temp"' EXIT
mkdir -p "$temp/bin"

cat > "$temp/bin/git" <<'FAKE_GIT'
#!/usr/bin/env bash
set -euo pipefail
case "$1 $2" in
  "status --porcelain") printf '%s' "${FAKE_GIT_STATUS:-}" ;;
  "rev-parse --short") printf '%s\n' abc1234 ;;
  *) exit 2 ;;
esac
FAKE_GIT

cat > "$temp/bin/aws" <<'FAKE_AWS'
#!/usr/bin/env bash
set -euo pipefail
printf '%q ' "$@" >> "$FAKE_AWS_LOG"
printf '\n' >> "$FAKE_AWS_LOG"
case "$1 $2" in
  "configure get")
    [[ ${FAKE_CONFIG_REGION+x} ]] && printf '%s\n' "$FAKE_CONFIG_REGION"
    ;;
  "sts get-caller-identity")
    if [[ ${FAKE_STS_RESULT:-ok} != ok ]]; then
      printf 'Unable to locate credentials\n' >&2
      exit 255
    fi
    printf '%s\t%s\n' \
      "${FAKE_ACCOUNT:-000000000000}" \
      "${FAKE_ARN:-arn:aws:iam::000000000000:user/test-user}"
    ;;
  "ecr describe-images")
    case "${FAKE_DESCRIBE_RESULT:-missing}" in
      exists) exit 0 ;;
      missing) printf 'An error occurred (ImageNotFoundException): image absent\n' >&2; exit 254 ;;
      repository-missing) printf 'An error occurred (RepositoryNotFoundException): repository absent\n' >&2; exit 254 ;;
      auth) printf 'An error occurred (AccessDeniedException): access denied\n' >&2; exit 254 ;;
      network) printf 'Could not connect to the endpoint URL\n' >&2; exit 255 ;;
      unknown) printf 'unexpected service failure\n' >&2; exit 1 ;;
    esac
    ;;
  "ecr get-login-password")
    [[ ${FAKE_LOGIN_RESULT:-ok} == ok ]] || exit 1
    printf 'secret-password\n'
    ;;
  *) exit 2 ;;
esac
FAKE_AWS

cat > "$temp/bin/docker" <<'FAKE_DOCKER'
#!/usr/bin/env bash
set -euo pipefail
printf '%q ' "$@" >> "$FAKE_DOCKER_LOG"
printf '\n' >> "$FAKE_DOCKER_LOG"
case "${1:-} ${2:-}" in
  "buildx version" | "info ") exit 0 ;;
  "login --username")
    password=$(cat)
    [[ "$password" == secret-password ]] || exit 1
    [[ ${FAKE_DOCKER_LOGIN_RESULT:-ok} == ok ]]
    ;;
  "buildx build")
    while [[ $# -gt 0 ]]; do
      if [[ "$1" == --metadata-file ]]; then
        if [[ ${FAKE_METADATA_RESULT:-digest} == digest ]]; then
          printf '{"containerimage.digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}\n' > "$2"
        else
          printf '{}\n' > "$2"
        fi
        break
      fi
      shift
    done
    ;;
  *) exit 2 ;;
esac
FAKE_DOCKER
chmod +x "$temp/bin/git" "$temp/bin/aws" "$temp/bin/docker"

export PATH="$temp/bin:$PATH"
export FAKE_AWS_LOG="$temp/aws.log"
export FAKE_DOCKER_LOG="$temp/docker.log"

reset_logs() {
  : > "$FAKE_AWS_LOG"
  : > "$FAKE_DOCKER_LOG"
}

expect_failure() {
  local description=$1
  shift
  if "$@" >"$temp/failure.out" 2>&1; then
    printf 'FAIL: expected failure: %s\n' "$description" >&2
    exit 1
  fi
}

assert_no_push() {
  if grep -Fq -- '--push' "$FAKE_DOCKER_LOG"; then
    printf 'FAIL: failure path attempted a push\n' >&2
    exit 1
  fi
}

reset_logs
output=$($builder local)
grep -Fq 'buildx build --target production --load --tag traversal-connector:prerelease-abc1234 .' "$FAKE_DOCKER_LOG"
grep -Fq 'Loaded local prerelease image: traversal-connector:prerelease-abc1234' <<<"$output"
[[ ! -s "$FAKE_AWS_LOG" ]]

reset_logs
$builder local --repository example.test/team/connector --tag prerelease-demo.1 >/dev/null
grep -Fq -- '--tag example.test/team/connector:prerelease-demo.1' "$FAKE_DOCKER_LOG"

reset_logs
output=$($builder push --region us-west-2 --ecr-repository team/connector)
grep -Fq "sts get-caller-identity --region us-west-2 --query \[Account\,Arn\] --output text" "$FAKE_AWS_LOG"
grep -Fq 'ecr describe-images --region us-west-2 --repository-name team/connector --image-ids imageTag=prerelease-abc1234' "$FAKE_AWS_LOG"
grep -Fq 'ecr get-login-password --region us-west-2' "$FAKE_AWS_LOG"
grep -Fq 'login --username AWS --password-stdin 000000000000.dkr.ecr.us-west-2.amazonaws.com' "$FAKE_DOCKER_LOG"
grep -Fq -- '--platform linux/amd64\,linux/arm64' "$FAKE_DOCKER_LOG"
grep -Fq -- '--target production' "$FAKE_DOCKER_LOG"
grep -Fq -- '--sbom=true' "$FAKE_DOCKER_LOG"
grep -Fq -- '--provenance=mode=max' "$FAKE_DOCKER_LOG"
grep -Fq -- '--tag 000000000000.dkr.ecr.us-west-2.amazonaws.com/team/connector:prerelease-abc1234' "$FAKE_DOCKER_LOG"
grep -Fq 'Published unsigned prerelease image: 000000000000.dkr.ecr.us-west-2.amazonaws.com/team/connector@sha256:aaaaaaaa' <<<"$output"

reset_logs
$builder push --profile test-profile --region eu-central-1 >/dev/null
[[ $(grep -Fc -- '--profile test-profile' "$FAKE_AWS_LOG") -eq 3 ]]

reset_logs
FAKE_ARN=arn:aws-cn:iam::000000000000:user/test-user \
  $builder push --region cn-north-1 >/dev/null
grep -Fq 'login --username AWS --password-stdin 000000000000.dkr.ecr.cn-north-1.amazonaws.com.cn' "$FAKE_DOCKER_LOG"

reset_logs
AWS_REGION=ap-southeast-2 AWS_DEFAULT_REGION=us-east-1 $builder push >/dev/null
grep -Fq -- '--region ap-southeast-2' "$FAKE_AWS_LOG"
if grep -Fq 'configure get' "$FAKE_AWS_LOG"; then
  printf 'FAIL: configured region queried despite AWS_REGION\n' >&2
  exit 1
fi

reset_logs
env -u AWS_REGION -u AWS_DEFAULT_REGION FAKE_CONFIG_REGION=ca-central-1 \
  "$builder" push --profile config-profile >/dev/null
grep -Fq 'configure get region --profile config-profile' "$FAKE_AWS_LOG"
grep -Fq -- '--profile config-profile --region ca-central-1' "$FAKE_AWS_LOG"

FAKE_GIT_STATUS=' M changed.go' expect_failure "dirty worktree" "$builder" local
expect_failure "stable version tag" "$builder" local --tag v1.2.3
expect_failure "latest tag" "$builder" push --region us-west-2 --tag latest
expect_failure "invalid ECR repository" "$builder" push --region us-west-2 --ecr-repository 'Team Repo:tag'

reset_logs
FAKE_DESCRIBE_RESULT=exists expect_failure "existing tag" "$builder" push --region us-west-2
assert_no_push
if grep -Fq 'login --username' "$FAKE_DOCKER_LOG"; then
  printf 'FAIL: existing tag attempted Docker login\n' >&2
  exit 1
fi

reset_logs
FAKE_DESCRIBE_RESULT=repository-missing expect_failure \
  "missing repository" "$builder" push --region us-west-2
grep -Fq 'must be created before publishing' "$temp/failure.out"
assert_no_push

for result in auth network unknown; do
  reset_logs
  FAKE_DESCRIBE_RESULT=$result expect_failure "$result describe failure" "$builder" push --region us-west-2
  assert_no_push
done

reset_logs
FAKE_ACCOUNT=not-an-account expect_failure "malformed account" "$builder" push --region us-west-2
assert_no_push

reset_logs
FAKE_ARN=arn:aws-iso:iam::000000000000:user/test-user expect_failure \
  "unknown partition" "$builder" push --region us-iso-east-1
grep -Fq 'unsupported AWS partition' "$temp/failure.out"
assert_no_push

reset_logs
FAKE_STS_RESULT=error expect_failure "STS failure" "$builder" push --region us-west-2
grep -Fq 'Unable to locate credentials' "$temp/failure.out"
grep -Fq 'could not resolve AWS caller identity' "$temp/failure.out"
assert_no_push

reset_logs
expect_failure "unresolved region" env -u AWS_REGION -u AWS_DEFAULT_REGION \
  FAKE_CONFIG_REGION= "$builder" push
assert_no_push

reset_logs
FAKE_LOGIN_RESULT=fail expect_failure "AWS login failure" "$builder" push --region us-west-2
assert_no_push

reset_logs
FAKE_DOCKER_LOGIN_RESULT=fail expect_failure "Docker login failure" "$builder" push --region us-west-2
assert_no_push

reset_logs
FAKE_METADATA_RESULT=missing expect_failure "missing digest metadata" "$builder" push --region us-west-2
grep -Fq 'push succeeded but Buildx did not report an image digest' "$temp/failure.out"
grep -Fq -- '--push' "$FAKE_DOCKER_LOG"

printf 'All prerelease image builder tests passed.\n'
