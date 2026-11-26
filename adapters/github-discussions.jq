# For local JSON arrays of repositories' issue, pull request or comment objects.
.[] |
  {source: "github", path: (.html_url // error("missing html_url")),
   revision: .updated_at, content: ([.title, .body, .diff_hunk] | map(select(type == "string")) | join("\n"))}
