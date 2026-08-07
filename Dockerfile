FROM python:3.11-slim

WORKDIR /app

# Install dependencies first so this layer is cached across code-only changes.
COPY pyproject.toml README.md ./
COPY hunterbot ./hunterbot
RUN pip install --no-cache-dir ".[semantic,llm]"

# Persisted database and generated reports live here; mount a volume at
# runtime (e.g. `-v hunterbot-data:/data`) to keep them across container runs.
ENV HUNTERBOT_DATABASE_URL=sqlite:////data/hunterbot.db
VOLUME ["/data"]

ENTRYPOINT ["hunterbot"]
CMD ["--help"]
