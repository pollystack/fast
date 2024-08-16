# Start from a Go base image
FROM golang:1.21-alpine as builder

# Set the working directory inside the container
WORKDIR /app

# Copy the entire project
COPY fast-server .

# Download all dependencies (this will create go.sum if it doesn't exist)
RUN go mod download

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o fast_server .

# Start a new stage from scratch
FROM alpine:latest

# Install ca-certificates
RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy the pre-built binary file from the previous stage
COPY --from=builder /app/fast_server .

# Copy the config file
COPY config.yaml.example /etc/fast/config.yaml

# Create necessary directories
RUN mkdir -p /var/www/fast /etc/fast/ssl /var/log/fast

# Expose ports
EXPOSE 80 443

# Command to run the executable
CMD ["./fast_server"]