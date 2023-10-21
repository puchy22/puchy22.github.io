FROM jekyll:stable

VOLUME /jekyll

WORKDIR /jekyll
COPY --chown=jekyll:jekyll . /jekyll
RUN bundle install && jekyll build
