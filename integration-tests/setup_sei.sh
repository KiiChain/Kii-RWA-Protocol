#!/bin/bash

# Install Sei Chain
REPO_DIR=".sei-chain"

# Check if the repository is already cloned
if [ ! -d "$REPO_DIR" ]; then
    echo "Cloning Sei Chain repository..."
    git clone https://github.com/sei-protocol/sei-chain.git "$REPO_DIR"
    cd "$REPO_DIR" || exit
else
    cd "$REPO_DIR" || exit
fi

echo -e "\nInitializing and starting Sei Chain...\n"
./scripts/initialize_local_chain.sh 
