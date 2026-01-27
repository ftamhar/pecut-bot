# Build stage
FROM golang:1.24.5-bullseye AS builder

# Install build dependencies for CGO
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
# CGO_ENABLED=1 is required for sqlite3 driver
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o app .

# Runtime stage
FROM debian:bullseye-slim

# Install runtime dependencies for SQLite
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/app .

# Create directory for database (if needed)
RUN mkdir -p /app/data

# Expose any ports if needed (currently none, but can be added)
# EXPOSE 8080

# Set entrypoint with default command
# Users should override with their own token, chat ID, and thread ID
ENTRYPOINT ["./app"]

# Default command (should be overridden with actual values)
CMD ["-token", "", "-id", "0", "-thread", "0", "-v"]
