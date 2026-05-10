#!/usr/bin/env bash

echo "Cleaning up sample kind clusters ..."
kind delete cluster --name cluster-a 2>/dev/null || true
kind delete cluster --name cluster-b 2>/dev/null || true

echo "Cleaning up generated certificates ..."
rm -f certs/ca-*-key.pem certs/ca-*.pem
