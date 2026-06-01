# FoxGuard Security Portal — Deployment & Onboarding Guide

This document outlines the operational instructions required to spin up the FoxGuard ecosystem locally or trigger automated infrastructure delivery.

## Local Application Development Quickstart
To isolate modifications and verify backend routes locally on port 5000:
# 1. Clone the master repository branch:
git clone https://github.com/robinsju/foxguard-security.git
cd foxguard-security
# Create and activate a localized virtual environment:
python3 -m venv venv
source venv/bin/activate
# Install required application software dependencies
pip install -r requirements.txt
# Initialize the server locally
python app.py
