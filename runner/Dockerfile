FROM ghcr.io/actions/actions-runner@sha256:759a1d94a15b05941aba5196974ff43fe15b4cbba29b694b35cbc32a1166b232
USER root
RUN userdel ubuntu && groupmod -g 1000 runner && usermod -u 1000 -g 1000 -G runner runner && chown -R 1000:1000 /home/runner
ENV HOME=/home/runner
USER 1000:1000
WORKDIR /home/runner
ENTRYPOINT ["/home/runner/run.sh"]
