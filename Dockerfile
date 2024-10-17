# Use the official Rust image
FROM docker.io/rust:latest

# Set the working directory
WORKDIR /app/tls_interceptor_proxy

# Copy your project files into the container
COPY . .

# Build your project (optional, you can skip this step if you want to run cargo run directly)
RUN cargo build --release

# Command to run your application
CMD ["cargo", "run"]

