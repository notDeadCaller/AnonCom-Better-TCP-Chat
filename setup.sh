#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

echo "--- [1/3] Installing System Dependencies (Requires sudo) ---"
sudo apt-get update
sudo apt-get install -y git cmake gcc ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz python3-yaml valgrind

echo "--- [2/3] Cloning and Building liboqs (This may take a few minutes) ---"

# Check if liboqs directory already exists
if [ -d "liboqs" ]; then
    echo "liboqs directory already exists. Skipping clone."
else
    git clone --branch main https://github.com/open-quantum-safe/liboqs.git
fi

# Build liboqs
cd liboqs
mkdir -p build
cd build
cmake -GNinja -DOQS_USE_OPENSSL=ON ..
ninja

# Go back to the project's root directory
cd ../..

echo "--- [3/3] Setup Complete! ---"
echo "You can now compile the project by running: make"
echo "To run the client, use: ./runClient.sh"
