# ClusterFuzzLite build container. `build_fuzzers@v1` (invoked from
# .github/workflows/cflite_pr.yml / cflite_batch.yml) overrides this
# initial clone with the actual PR/HEAD commit before running build.sh —
# this `git clone` just needs to seed a checkout for it to update.
FROM gcr.io/oss-fuzz-base/base-builder-rust

RUN git clone --depth 1 https://github.com/cameronaaron/novachannel $SRC/novachannel
COPY .clusterfuzzlite/build.sh $SRC/
WORKDIR $SRC/novachannel
