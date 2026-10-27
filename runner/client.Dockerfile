FROM python:3.14-slim-trixie@sha256:82abc9f53600280b0757126f83c5a7d47088592d2acb6b4c0b9e97f76865508c
COPY dependencies/ /opt/dependencies/
RUN chmod -R a+rX /opt/dependencies
ENV PYTHONPATH=/opt/dependencies DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1
