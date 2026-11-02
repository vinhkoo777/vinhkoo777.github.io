#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
runtime_root="$(dirname -- "$project_root")/.runtime"
export GEM_HOME="$runtime_root/wsl-gems"
export PATH="$GEM_HOME/bin:$PATH"
export BUNDLE_USER_HOME="$runtime_root/wsl-bundler"
export JEKYLL_ENV=production
cd -- "$project_root"

case "${1:-serve}" in
  install)
    if ! gem list --installed --exact bundler --version 2.6.9 >/dev/null; then
      gem install bundler --version 2.6.9 --no-document
    fi
    bundle config set --local path vendor/bundle
    BUNDLE_TIMEOUT=15 BUNDLE_RETRY=1 bundle install --jobs 4
    ;;
  build) bundle exec jekyll build --trace "${@:2}" ;;
  check) bundle exec htmlproofer _site --disable-external ;;
  pages-check)
    bundle exec jekyll build --baseurl /preview-blog --destination .runtime/pages-smoke/preview-blog
    bundle exec htmlproofer .runtime/pages-smoke --disable-external
    ;;
  serve) bundle exec jekyll serve --host 127.0.0.1 --port 4000 --force_polling "${@:2}" ;;
  lock) bundle lock --add-platform x86_64-linux ;;
  *) printf 'Usage: bash tools/local.sh [install|build|check|pages-check|serve|lock]\n' >&2; exit 2 ;;
esac
