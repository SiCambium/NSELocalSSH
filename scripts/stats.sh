#!/bin/sh
# Reports release downloads and repository traffic.
#
# GitHub shows none of this in its web UI. The Releases page lists each
# asset's name, size and date and no download count at all — the counts
# exist only in the API. Traffic (views and clones) does have a UI page,
# Insights -> Traffic, but it needs push access and keeps only 14 days.
#
# The raw download count is close to meaningless on its own, so this
# reports two numbers. Every release has a FLOOR: a count that even
# nse-status_<v>_linux_armv6 and _freebsd_amd64 reach. Nobody downloads
# armv6, armv7 and FreeBSD in precisely equal numbers; that floor is
# machinery walking the asset list. Subtracting it leaves the downloads
# where a human picked a file, reported here as "signal".
#
# Two contributors to that floor are known. Release automation used to
# download every asset to checksum it, adding one per asset per release
# until .github/workflows/release.yml was changed to sum build artifacts
# instead; releases up to v0.7 still carry it. The rest is bots.
#
# The floor is a heuristic, not ground truth: it assumes the least-wanted
# asset got zero real downloads, so signal reads slightly low. It is far
# closer than the raw total.
#
# Counts are cumulative per asset and never decay, so an old release and
# a new one are not comparable without dividing by age. The counter is
# also not live — a download does not appear for some minutes — so
# short-interval deltas mean nothing.
#
# Usage: sh scripts/stats.sh [owner/repo]
set -eu

repo="${1:-SiCambium/NSELocalSSH}"

command -v gh >/dev/null 2>&1 || {
	echo "stats: needs the GitHub CLI (gh). See https://cli.github.com" >&2
	exit 1
}
gh auth status >/dev/null 2>&1 || {
	echo "stats: gh is not authenticated. Run: gh auth login" >&2
	exit 1
}

echo "== $repo =="
echo

# --- Downloads ------------------------------------------------------------

echo "Downloads (raw = every request; signal = raw minus the per-release floor)"
echo
gh api "repos/$repo/releases" --paginate --jq '
	.[] | select(.assets | length > 0) |
	(.assets | length) as $n |
	([.assets[].download_count] | add) as $total |
	([.assets[].download_count] | min) as $floor |
	[.tag_name, .published_at[0:10], $total, $n, $floor, ($floor * $n), ($total - $floor * $n)] | @tsv
' | awk -F'\t' '
	BEGIN { printf "  %-9s %-11s %7s %7s %7s %9s\n", "release", "published", "raw", "assets", "floor", "signal"
	        printf "  %s\n", "---------------------------------------------------------" }
	{ raw += $3; sig += $7
	  printf "  %-9s %-11s %7d %7d %7d %9d\n", $1, $2, $3, $4, $5, $7 }
	END { printf "  %s\n", "---------------------------------------------------------"
	      printf "  %-9s %-11s %7d %7s %7s %9d\n", "TOTAL", "", raw, "", "", sig
	      if (raw > 0) printf "\n  %d of %d recorded downloads (%.0f%%) are machine traffic.\n", raw - sig, raw, (raw - sig) * 100 / raw }
'
echo

# --- Latest release, by asset ---------------------------------------------

latest="$(gh api "repos/$repo/releases" --jq '[.[] | select(.assets | length > 0)][0].tag_name // empty')"

if [ -n "$latest" ]; then
	floor="$(gh api "repos/$repo/releases/tags/$latest" --jq '[.assets[].download_count] | min')"
	echo "Latest release $latest, by asset (floor $floor; above it, someone chose the file)"
	echo
	gh api "repos/$repo/releases/tags/$latest" --jq '.assets[] | [.download_count, .name] | @tsv' \
		| sort -rn \
		| awk -F'\t' -v f="$floor" '
			$1 > f { printf "  %5d  %-34s +%d\n", $1, $2, $1 - f; next }
			       { printf "  %5d  %s\n", $1, $2 }
		'
	echo
fi

# --- Traffic --------------------------------------------------------------
# Needs push access. A reader without it gets 403, which is not an error
# worth failing the whole script over.

if gh api "repos/$repo/traffic/views" >/dev/null 2>&1; then
	echo "Traffic (14-day window, all GitHub retains)"
	echo
	gh api "repos/$repo/traffic/views" --jq '"  views   \(.count) total, \(.uniques) unique"'
	gh api "repos/$repo/traffic/clones" --jq '"  clones  \(.count) total, \(.uniques) unique"'
	echo
	echo "  most recent days:"
	gh api "repos/$repo/traffic/views" --jq '.views[-5:][] | "    \(.timestamp[0:10])  \(.count) views, \(.uniques) unique"'
	echo
	echo "  referrers:"
	gh api "repos/$repo/traffic/popular/referrers" \
		--jq '.[] | "    \(.referrer)  \(.count) (\(.uniques) unique)"' | head -8
	echo
else
	echo "Traffic: unavailable (needs push access to $repo)"
	echo
fi

# --- Repository -----------------------------------------------------------

gh api "repos/$repo" --jq '"Stars \(.stargazers_count)   forks \(.forks_count)   open issues+PRs \(.open_issues_count)"'
