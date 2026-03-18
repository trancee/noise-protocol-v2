#!/usr/bin/env bash
#
# maven-api.sh — Query Maven Central for artifact information.
#
# Usage:
#   ./scripts/maven.sh search <query>           Search artifacts by keyword
#   ./scripts/maven.sh versions <group> <artifact>  List published versions
#   ./scripts/maven.sh latest <group> <artifact>    Show latest version
#   ./scripts/maven.sh info <group> <artifact> [version]  Show artifact details
#   ./scripts/maven.sh pom <group> <artifact> <version>   Fetch the POM file
#   ./scripts/maven.sh status                   Check deployment status (requires auth)
#
# Environment:
#   MAVEN_CENTRAL_USERNAME / MAVEN_CENTRAL_PASSWORD  Required for 'status' command
#
set -euo pipefail

BASE_URL="https://central.sonatype.com"
SEARCH_URL="https://search.maven.org/solrsearch/select"
REPO_URL="https://repo1.maven.org/maven2"

red()    { printf '\033[0;31m%s\033[0m\n' "$*"; }
green()  { printf '\033[0;32m%s\033[0m\n' "$*"; }
bold()   { printf '\033[1m%s\033[0m\n' "$*"; }
dim()    { printf '\033[2m%s\033[0m\n' "$*"; }

usage() {
    sed -n '3,12p' "$0" | sed 's/^# \?//'
    exit 1
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || { red "Error: '$1' is required but not found."; exit 1; }
}

require_cmd curl
require_cmd jq

# ── Commands ──────────────────────────────────────────────────────────

cmd_search() {
    local query="${1:?Usage: maven-api.sh search <query>}"
    local encoded_query
    encoded_query=$(printf '%s' "$query" | jq -sRr @uri)
    local response
    response=$(curl -sf "${SEARCH_URL}?q=${encoded_query}&rows=20&wt=json")

    local count
    count=$(echo "$response" | jq '.response.numFound')
    bold "Found $count artifacts matching '$query':"
    echo

    echo "$response" | jq -r '
        .response.docs[] |
        "  \(.g):\(.a):\(.latestVersion)  (\(.versionCount) versions)"
    '
}

cmd_versions() {
    local group="${1:?Usage: maven-api.sh versions <group> <artifact>}"
    local artifact="${2:?Usage: maven-api.sh versions <group> <artifact>}"
    local response
    response=$(curl -sf "${SEARCH_URL}?q=g:${group}+AND+a:${artifact}&core=gav&rows=100&wt=json")

    local count
    count=$(echo "$response" | jq '.response.numFound')
    bold "$group:$artifact — $count version(s):"
    echo

    echo "$response" | jq -r '.response.docs[] | "  \(.v)  (\(.timestamp / 1000 | strftime("%Y-%m-%d")))"'
}

cmd_latest() {
    local group="${1:?Usage: maven-api.sh latest <group> <artifact>}"
    local artifact="${2:?Usage: maven-api.sh latest <group> <artifact>}"
    local response
    response=$(curl -sf "${SEARCH_URL}?q=g:${group}+AND+a:${artifact}&rows=1&wt=json")

    local version
    version=$(echo "$response" | jq -r '.response.docs[0].latestVersion // empty')

    if [[ -z "$version" ]]; then
        red "No artifact found for $group:$artifact"
        exit 1
    fi

    echo "$version"
}

cmd_info() {
    local group="${1:?Usage: maven-api.sh info <group> <artifact> [version]}"
    local artifact="${2:?Usage: maven-api.sh info <group> <artifact> [version]}"
    local version="${3:-}"
    local response

    if [[ -n "$version" ]]; then
        response=$(curl -sf "${SEARCH_URL}?q=g:${group}+AND+a:${artifact}+AND+v:${version}&rows=1&wt=json")
    else
        response=$(curl -sf "${SEARCH_URL}?q=g:${group}+AND+a:${artifact}&rows=1&wt=json")
    fi

    local found
    found=$(echo "$response" | jq '.response.numFound')
    if [[ "$found" == "0" ]]; then
        red "Artifact not found: $group:$artifact${version:+:$version}"
        exit 1
    fi

    echo "$response" | jq -r '
        .response.docs[0] |
        "Group:      \(.g)",
        "Artifact:   \(.a)",
        "Version:    \(.latestVersion // .v)",
        "Packaging:  \(.p // "jar")",
        "Versions:   \(.versionCount // "N/A")",
        "Updated:    \((.timestamp // 0) / 1000 | strftime("%Y-%m-%d %H:%M UTC"))"
    '

    local group_path="${group//.//}"
    echo
    dim "Maven:"
    echo "  <dependency>"
    echo "      <groupId>${group}</groupId>"
    echo "      <artifactId>${artifact}</artifactId>"
    echo "      <version>$(echo "$response" | jq -r '.response.docs[0] | .latestVersion // .v')</version>"
    echo "  </dependency>"
    echo
    dim "Gradle:"
    echo "  implementation(\"${group}:${artifact}:$(echo "$response" | jq -r '.response.docs[0] | .latestVersion // .v')\")"
}

cmd_pom() {
    local group="${1:?Usage: maven-api.sh pom <group> <artifact> <version>}"
    local artifact="${2:?Usage: maven-api.sh pom <group> <artifact> <version>}"
    local version="${3:?Usage: maven-api.sh pom <group> <artifact> <version>}"

    local group_path="${group//.//}"
    local url="${REPO_URL}/${group_path}/${artifact}/${version}/${artifact}-${version}.pom"

    curl -sf "$url" || { red "POM not found at $url"; exit 1; }
}

cmd_status() {
    local username="${MAVEN_CENTRAL_USERNAME:?Set MAVEN_CENTRAL_USERNAME}"
    local password="${MAVEN_CENTRAL_PASSWORD:?Set MAVEN_CENTRAL_PASSWORD}"
    local token
    token=$(printf '%s:%s' "$username" "$password" | base64)

    bold "Recent deployments:"
    echo

    local response
    response=$(curl -sf \
        -H "Authorization: Bearer ${token}" \
        "${BASE_URL}/api/v1/publisher/published?namespace=noise.protocol&limit=10" 2>/dev/null || echo "[]")

    if [[ "$response" == "[]" || -z "$response" ]]; then
        dim "  No deployments found (or authentication failed)."
        dim "  Ensure MAVEN_CENTRAL_USERNAME and MAVEN_CENTRAL_PASSWORD are set."
        return
    fi

    echo "$response" | jq -r '
        .[] |
        "  \(.deploymentName // "unnamed")  \(.deploymentState)  \(.deploymentId[:8])..."
    ' 2>/dev/null || dim "  Could not parse response."
}

# ── Main ──────────────────────────────────────────────────────────────

case "${1:-}" in
    search)   shift; cmd_search "$@" ;;
    versions) shift; cmd_versions "$@" ;;
    latest)   shift; cmd_latest "$@" ;;
    info)     shift; cmd_info "$@" ;;
    pom)      shift; cmd_pom "$@" ;;
    status)   shift; cmd_status "$@" ;;
    *)        usage ;;
esac
