FROM jekyll:stable

WORKDIR /jekyll
COPY . /jekyll
RUN jekyll build
