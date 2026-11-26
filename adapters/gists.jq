# Accept one exported gist object containing the full text of every file.
. as $gist | .files | to_entries[] |
  if .value.truncated or (.value.content | type != "string")
  then error("incomplete gist export") else
  {source: "gist", path: ($gist.id + "/" + .key), revision: $gist.history[0].version,
   content: .value.content}
  end
