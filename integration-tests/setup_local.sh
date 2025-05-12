#!/bin/bash

# Install KiiChain
REPO_DIR=".kiichain"

# Check if the repository is already cloned
if [ ! -d "$REPO_DIR" ]; then
    echo "Cloning KiiChain repository..."
    git clone https://github.com/KiiChain/kiichainV3.git "$REPO_DIR"
    cd "$REPO_DIR" || exit
    make install
    source ~/.bash_profile
else
    cd "$REPO_DIR" || exit
fi

echo -e "\nStarting KiiChain...\n"
kiichaind start