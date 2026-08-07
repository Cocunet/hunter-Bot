FROM python:3.11-slim

WORKDIR /app

# Install dependencies first so this layer is cached across code-only changes.
COPY pyproject.toml README.md ./
COPY hunterbot ./hunterbot
RUN pip install --no-cache-dir ".[semantic,llm,api]"

# Persisted database and generated reports live here; mount a volume at
# runtime (e.g. `-v hunterbot-data:/data`) to keep them across container runs.
ENV HUNTERBOT_DATABASE_URL=sqlite:////data/hunterbot.db
VOLUME ["/data"]

# Only relevant when running `hunterbot serve --host 0.0.0.0`; harmless
# otherwise (the CLI subcommands don't bind a port).
EXPOSE 8000

ENTRYPOINT ["hunterbot"]
CMD ["--help"]
