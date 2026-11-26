# Supply the export-relative day filename in $path.
.[] | select(.text | type == "string") |
  {source: "slack", path: $path, revision: .ts, content: .text}
