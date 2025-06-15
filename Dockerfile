# Stage 1: Build the Go application
FROM golang:1.23-alpine AS builder

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go mod
COPY /src/go.mod ./

# Copy the source code into the container
COPY /src .

# Build the Go app
# CGO_ENABLED=0 prevents the usage of Cgo for a static binary
# GOOS=linux ensures the binary is built for Linux
# -ldflags="-w -s" reduces the size of the binary by stripping debug information
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /app/echo-request .

# Stage 2: Create the final lightweight image
FROM alpine:latest

WORKDIR /app

COPY --from=builder /app/echo-request .

# Expose port 8080 (update if your application listens on a different port)
EXPOSE 8443

# Command to run the executable
CMD ["./echo-request"]