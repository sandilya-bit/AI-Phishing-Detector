# System Architecture Diagram

This file contains the detailed layout flow diagram of PhishGuard AI using Mermaid notation.

```mermaid
graph TD
    %% Define styles
    classDef client fill:#12121a,stroke:#ff003c,stroke-width:2px,color:#fff;
    classDef backend fill:#12121a,stroke:#00e5ff,stroke-width:2px,color:#fff;
    classDef storage fill:#12121a,stroke:#ffd600,stroke-width:2px,color:#fff;

    %% Nodes
    User([User Client UI]):::client
    API[FastAPI Router: main.py]:::backend
    Parser[Email Parser Service]:::backend
    ML[ML Inference Service]:::backend
    Heuristics[Heuristics Engine]:::backend
    DB[(SQLite DB: phishguard.db)]:::storage

    %% Flows
    User -->|EML, TXT, MSG upload or Pasted text| API
    API -->|Raw input payload| Parser
    Parser -->|Metadata & Links| Heuristics
    Parser -->|Raw email body text| ML
    Heuristics -->|Domain, Unicode, Urgency flags| API
    ML -->|DistilBERT confidence probabilities| API
    API -->|Consolidated Threat Score| DB
    API -->|Combined JSON Scan Report| User
```

## System Execution Sequence

1. **Upload**: User drags an `.eml` file into the dashboard.
2. **Parsing**: The parser extracts headers and parses message body attachments.
3. **Execution**:
   - The ML service runs TF-IDF vectorization and classifies text.
   - The Heuristics engine inspects links for typosquatting and checks header consistency.
4. **Resolution**: The API resolves ML labels vs heuristics scores and computes a threat rating.
5. **Logging**: The transaction details are saved into the SQLite database.
6. **Rendering**: The JSON payload is returned, updating the UI widgets.
