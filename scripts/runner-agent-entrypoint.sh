#!/bin/sh
set -eu

secret_dir=/run/buzz-secrets
if [ ! -d "$secret_dir" ]; then
  echo "buzz-agent runtime: secret mount is missing" >&2
  exit 1
fi

for secret_file in "$secret_dir"/*; do
  [ -f "$secret_file" ] || continue
  variable_name=${secret_file##*/}
  case "$variable_name" in
    [A-Z_]*)
      case "$variable_name" in
        *[!A-Z0-9_]*)
          echo "buzz-agent runtime: invalid secret variable name" >&2
          exit 1
          ;;
      esac
      ;;
    *)
      echo "buzz-agent runtime: invalid secret variable name" >&2
      exit 1
      ;;
  esac
  variable_value=$(cat "$secret_file")
  export "$variable_name=$variable_value"
done

exec /usr/local/bin/buzz-acp
