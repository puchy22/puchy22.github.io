podman run --rm -it -v "/srv/jekyll:/srv/jekyll:Z" \
  -e JEKYLL_ROOTLESS=1 -e BUNDLE_APP_CONFIG='.bundle' \
  -w=/srv/jekyll --network=host jekyll/jekyll:stable \
  sh -c "bundle install && jekyll build && bundle exec jekyll serve"
