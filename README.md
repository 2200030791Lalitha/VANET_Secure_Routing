# VANET Secure Routing Protocol Simulation

## Overview

This project implements a secure routing protocol for **Vehicular Ad Hoc Networks (VANET)** using cryptographic techniques (digital signatures and hash functions). The aim is to ensure data integrity and authenticity, mitigating common VANET-specific attacks such as impersonation and data tampering.

The simulation is carried out using:
- NS-2 / NS-3 / OMNeT++ (for network simulation)
- Veins + SUMO (for realistic vehicular movement)
- Python (for demonstrating hashing mechanisms and visualizing performance metrics)

## Features

- Cryptographic hash functions: SHA256, MD5, SHA1, BLAKE2b, SHA3-256
- Message integrity verification using hashes
- Collision detection among vehicles
- Simulation of valid and tampered messages
- Graphs for hash computation time, vehicle speed, and position over time

## Requirements

- Python 3.7+
- Libraries:
  - `matplotlib`
  - `pandas`
  - `hashlib`
- NS-2/NS-3 or OMNeT++ with Veins and SUMO

## Running the Python Simulation

python hashing_simulation.py

## This script will:

    Simulate vehicle movement

    Generate and verify hashed messages

    Visualize hash performance

    Plot vehicle speed and position

## Performance Metrics

    Packet Delivery Ratio

    End-to-End Delay

    Throughput

    Hash Function Time Performance

    Security Effectiveness

## Protocol Highlights

    Lightweight and efficient design

    Cryptographic integrity checks using salted hash functions

    Capable of detecting message tampering and impersonation

    Compatible with real-world VANET scenarios

## Future Work

    Integrate actual digital signatures (e.g., RSA, ECDSA)

    Port Python simulation results back to NS-3 log analysis

    Explore machine learning-based anomaly detection

