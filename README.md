# VELOX

### AI Platform for Real-Time Cyber Threat Detection

    Proiect de Licență
    Author: Muntean Rareș

## Overview

**VELOX** is a modern cybersecurity platform designed to detect network anomalies and potential threats in real-time using Artificial Intelligence. Unlike traditional rule-based firewalls, VeloSentry leverages Machine Learning to analyze network traffic patterns, filter false positives, and adapt based on user feedback.

The system is composed of a decoupled microservices architecture featuring a high-performance Python detection engine that also includes the model for AI, a robust ASP.NET Core API, and a reactive Nuxt.js frontend.

## Architecture

The system is built on four main pillars, as illustrated in the architecture diagram:

1. **The Detection Engine (Python Backend)**

- **Packet Sniffing**: Uses Scapy to capture incoming network traffic in real-time.
- **Preprocessing**: Restructures raw packet data into feature vectors suitable for ML analysis.
- **AI/ML Core**: Runs inference to detect threats.
- **Filtering**: Filters out obvious false positives before transmission.
- **Batching**: Sends detected alerts in batches to the ASP.NET Core service to reduce HTTP overhead.

2. **The Orchestrator (ASP.NET Backend)**

- **API Gateway**: Serves as the central communication hub.
- **Authentication**: Manages user security using JWT (JSON Web Tokens).
- **Logic Handler**: Receives batched alerts from the Python service and processes them for storage.
- **Database Operations**: Manages all CRUD operations with PostgreSQL.

3. **The Dashboard (Nuxt.js Frontend)**

- **Visualization**: Displays real-time traffic trends and alerts via dynamic charts.
- **User Interaction**: Allows security analysts to view detailed threat logs.
- **RL Feedback Loop**: Users can rate specific AI outputs (+1 or -1). This data is sent back to the system to retrain and improve the AI model's accuracy.

4. **Persistence (PostgreSQL DB)**

- **Users Table**: Stores credentials and user profile data.
- **Threats Table**: Stores detected anomalies, timestamps, and severity levels.

## Getting Started

### Prerequisites
