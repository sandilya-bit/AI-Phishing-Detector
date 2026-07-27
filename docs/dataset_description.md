# Dataset Description

This manual describes the design and distribution schemas of the dataset built into PhishGuard AI.

## Dataset Profile

- **Source**: Synthetic generator mirroring real enterprise corporate threat feeds (`dataset/download_dataset.py`).
- **Format**: Comma Separated Values (CSV).
- **Target Location**: `dataset/email_dataset.csv`.
- **Total Records**: 360 balanced records.

---

## Class Distribution

To ensure stable classification performance during fallback model updates, the dataset features a balanced, three-class split:

| Class | Count | Description |
| ----- | ----- | ----------- |
| **Phishing** | 120 | Focuses on credential harvesting, wire fraud, typosquatted links, and brand impersonation. |
| **Spam** | 120 | Contains commercial advertisements, diet pills, online pharmacy campaigns, and sweepstakes. |
| **Legitimate** | 120 | Typical corporate emails, code reviews, meeting agendas, personal dinner plans, and standard receipts. |

---

## Phishing Scam Categories & Templates

1. **Password Reset Scams**: Phony security alerts asking users to lock or update credentials immediately.
2. **Fake Invoices**: Quickbooks or invoice templates claiming outstanding balances.
3. **Bank Alerts**: Login security triggers containing lookalike links (e.g. `chase-security-alert.com`).
4. **Delivery Scams**: DHL/FedEx templates stating shipments are held pending custom fee payments.
5. **CEO Fraud / Business Email Compromise**: Emails requesting gift cards or wire transfers.
6. **Prize / Lottery Scams**: Claims of lottery winnings requesting bank account details.
