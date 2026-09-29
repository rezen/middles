set positional-arguments

# List available recipes.
default:
    @just --list

# Build the development binary.
build:
    cargo build --locked

# Build the optimized release binary.
release:
    cargo build --release --locked

# Check compilation without producing a binary.
check:
    cargo check --all-targets --locked

# Format Rust sources.
fmt:
    cargo fmt

# Check Rust formatting without changing files.
fmt-check:
    cargo fmt --check

# Run Clippy with warnings treated as errors.
lint:
    cargo clippy --all-targets --locked -- -D warnings

# Run tests; optional arguments are passed to cargo test.
test *args:
    cargo test --locked "$@"

# Benchmark stats writes across SQLite, redb, and Fjall (isolated dependencies).
bench-stats *args:
    cargo run --release --locked --manifest-path benchmarks/stats/Cargo.toml -- "$@"

# Run the proxy; optional arguments are passed to middles.
run *args:
    cargo run --locked -- "$@"

# Validate a configuration file without starting the server.
config-check config="middles.example.toml":
    cargo run --locked -- --config "$1" --check

# Run formatting, lint, tests, and example configuration validation.
ci: fmt-check lint test config-check

# Opt-in live registry/client checks; requires Python, npm, pip, and Composer.
smoke: build
    python3 scripts/smoke.py

# Local-only Bundler checks using inert fixture gems; requires Ruby and Bundler.
ruby-smoke: build
    python3 scripts/rubygems-smoke.py

# Local signed APT fixture through Debian and Ubuntu clients; requires Docker and GPG.
apt-smoke: build
    python3 scripts/apt-compatibility.py --proxy

# Exercise the signed APT fixture through the production Docker image.
apt-docker-smoke: docker-build
    python3 scripts/apt-compatibility.py --proxy-image middles:local

# Opt-in isolated Homebrew client -> middles -> official GHCR smoke; see docs/homebrew.
homebrew-smoke *args: build
    python3 scripts/homebrew-smoke.py "$@"

# Observe an official formula dependency closure without downloading bottles.
homebrew-warm *args:
    python3 scripts/homebrew-warm.py "$@"

# Build the container image.
docker-build:
    docker compose build

# Build and start the container; retains data in a named volume.
docker-up:
    docker compose up --build --detach --wait

# Stop and remove containers while preserving the data volume.
docker-down:
    docker compose down

# Validate container health, shutdown, and persistent storage using local fixtures.
docker-test: docker-build
    python3 scripts/docker-smoke.py middles:local

# Generate Rust API documentation.
docs:
    cargo doc --locked --no-deps

# Remove Cargo build artifacts (keeps the proxy's data/cache directory).
clean:
    cargo clean
