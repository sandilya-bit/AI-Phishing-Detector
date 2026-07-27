"""
Dataset generator and downloader for the AI Phishing Email Detector.
Generates a robust, synthetic cybersecurity dataset of phishing, spam, and legitimate emails
to allow the training pipeline to run out of the box, with options for downloading larger public datasets.
"""

import os
import pandas as pd
import json

# Define output path
DATASET_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = os.path.join(DATASET_DIR, "email_dataset.csv")

# High-quality synthetic email templates to build a representative corpus
PHISHING_TEMPLATES = [
    # Credential Harvesting / Account Security
    "Subject: URGENT: Your account has been suspended!\nDear Customer, We detected suspicious activity on your account. Please log in immediately to verify your identity: http://security-verification-login-portal-microsoft.com/auth. Failure to verify within 24 hours will result in permanent suspension.",
    "Subject: Password Reset Request - Action Required\nHello, someone requested a password reset for your bank profile. If this was not you, please secure your account now by clicking here: http://secure-verify-chasebank-online.net/login. Please do this immediately to prevent unauthorized access.",
    "Subject: Microsoft Office 365: Verify your login credentials\nYour office account password expires today. To keep using your Outlook and OneDrive cloud applications, click here to keep current password: http://outlook-office365-update.xyz/verify-credential. Password expiration will happen in 3 hours.",
    
    # Financial Scam / Bank Alert
    "Subject: Alert: Transaction of $1,420.00 Approved\nWe approved a transfer of $1,420.00 from your account to John Doe. If you did not authorize this, cancel the payment now at http://paypal-dispute-resolution.net/transaction/resolve. Thank you, Paypal Fraud Protection Team.",
    "Subject: Chase Bank Notification: Unusual Activity Detected\nSecurity Alert: We noticed a login attempt from a new location (IP: 182.22.45.109). If this was not you, click here immediately to lock your account: http://chase-security-alert-center.com/lock-account. Avoid account freeze.",
    
    # Fake Invoice / Billing Scam
    "Subject: Invoice #847293 details from Quickbooks\nPlease find attached invoice #847293 for your recent order of software licenses. Amount Due: $2,850.00. Payment is past due. Review the invoice here: http://quickbooks-billing-pdf-viewer.com/invoices/847293.pdf and submit payment immediately.",
    "Subject: Outstanding Invoice - Urgent Payment Requested\nDear vendor, we have not received payment for invoice INV-2026-902. Please review the statement and send the payment of $4,900.00 to avoid late fees. Secure link: http://invoice-payment-gateway-sec.cc/inv/902.",
    
    # Delivery Scam
    "Subject: FedEx: Package delivery failed - Action Required\nYour parcel could not be delivered on 07/21/2026 due to an incorrect shipping address. Please update your home address and pay the redelivery fee of $1.50 at: http://fedex-redelivery-tracking-portal.com/update. Packages are held for only 48 hours.",
    "Subject: DHL Notification: Shipment Arrived at Hub\nDHL Express Shipment DHL98234729 has arrived at our local hub but is pending customs clearance fee of $3.50. Update details and pay fees here: http://dhl-express-clearance-fees.net/clearance. Delay will result in returning package.",

    # CEO Fraud / BEC
    "Subject: Are you at your desk?\nHi, I am currently in a meeting and cannot take calls. I need you to purchase 5 Apple gift cards of $100 each for a client gift. Send the codes to me via email as soon as possible. Mark this urgent. Thanks, CEO.",
    "Subject: Quick Request - Wire Transfer\nHey, can you initiate a wire transfer of $15,000 to our new supplier? I need this processed before the close of business today. Details are attached. Send confirmation once done. Thanks, Chief Executive Officer.",
    
    # Prize / Lottery Scam
    "Subject: CONGRATULATIONS! You won the Mega Millions Raffle\nYou have been selected as the grand prize winner of $1,000,000.00 cash! To claim your lottery prize, please contact our agent at claim-prize@win-lottery-claims.com with your full name, phone number, and bank account details.",
]

SPAM_TEMPLATES = [
    # Promotional / Advertisements
    "Subject: Lose 20 pounds in 2 weeks! Special offer\nGuaranteed weight loss pills! No exercise needed. All natural ingredients. Buy 1 get 1 free today only! Click here to order: http://cheap-diet-pills-discount-hub.com. Thousands of happy customers!",
    "Subject: Cheap Pharmacy Online - Order Levitra/Viagra today\nBest prices on the web! No prescription required. Discreet packaging and overnight shipping. Check our massive catalog of medication: http://cheap-meds-direct-24.com/shop. Order now!",
    "Subject: Get rich quick! Earn $5000/day working from home\nNo experience needed. Start making money from home today. All you need is a computer and 2 hours a day. Click link for details: http://earn-money-fast-today.net/register.",
    "Subject: Increase your Google website traffic now!\nDo you want more visitors to your website? We can guarantee 50,000 real visitors per month starting at just $29. Boost your sales today. Visit http://seo-traffic-boosters.net/plans.",
    "Subject: Lowest mortgage rates in years - Lock your rate!\nRefinance today and save thousands of dollars on your monthly mortgage payments. Quick approval in minutes. Apply here: http://low-rates-mortgage-advisor.com/apply.",
    "Subject: Exclusive Deal: 80% Off Designer Watches\nGet replica Rolex, Omega, and Tag Heuer watches at a fraction of the cost. Free shipping worldwide. Visit http://replica-designer-watches-shop.biz today.",
]

LEGITIMATE_TEMPLATES = [
    # Work Correspondence
    "Subject: Project Status Update Meeting - Tuesday 10 AM\nHi Team, just a reminder that our weekly project review is scheduled for Tuesday at 10 AM in Conference Room B. Please update your status slides in the shared drive before the meeting. Thanks, Project Manager.",
    "Subject: Code Review: Pull Request #412 - Auth Service\nHi Alex, I have submitted a pull request with the new authentication service implementation. Could you please review the changes when you have a moment? The code is available on our internal git repository.",
    "Subject: Action Required: Please submit your monthly timesheet\nHello everyone, this is a friendly reminder to submit your timesheets for this month by Friday at 5 PM. Please ensure all project codes are entered correctly. Contact HR if you have issues.",
    
    # Personal Emails
    "Subject: Plans for dinner this weekend?\nHey! Just checking in to see if you are free for dinner this Saturday. There is a new Italian restaurant downtown we should check out. Let me know what time works for you. Best, Sarah.",
    "Subject: Family Reunion photos shared with you\nHi, I have uploaded all the photos from the family reunion last Sunday to Google Photos. You can view them and download your favorites here: https://photos.google.com/share/family-reunion-2026. Hope you like them!",
    
    # Standard Transactional / Service Emails
    "Subject: Your receipt for Order #9832749\nThank you for your purchase from Tech Gear Online! Your order #9832749 has been processed and will ship within 2 business days. You can track your shipment status in your official account portal: https://www.techgearonline.com/account/orders.",
    "Subject: Github: Security Alert - Dependency Update available\nWe found a vulnerable dependency in one of your repositories. Please update the packaging library to version 2.4.1 to resolve the vulnerability. Review the advisory on Github security portal.",
    "Subject: Netflix: Confirming your subscription renewal\nThank you for being a Netflix member. This is to confirm your subscription has been renewed for another month. Your payment of $15.49 was charged to your card on file. If you have questions, visit our help center.",
]

def generate_synthetic_data(num_samples_per_class=100):
    """Generates a balanced dataset using combinations of typical features."""
    print("Generating high-quality synthetic cybersecurity dataset...")
    
    data = []
    
    # We will expand the base templates with minor variations to reach target size
    for idx in range(num_samples_per_class):
        # 1. Phishing
        p_template = PHISHING_TEMPLATES[idx % len(PHISHING_TEMPLATES)]
        p_body = p_template + f"\n\nSecurity Reference ID: PSG-98{idx}."
        data.append({"text": p_body, "label": "phishing"})
        
        # 2. Spam
        s_template = SPAM_TEMPLATES[idx % len(SPAM_TEMPLATES)]
        s_body = s_template + f"\n\nTo unsubscribe from this list, click here: http://unsubscribe-link-center.com/unsub/{idx}."
        data.append({"text": s_body, "label": "spam"})
        
        # 3. Legitimate (Ham)
        l_template = LEGITIMATE_TEMPLATES[idx % len(LEGITIMATE_TEMPLATES)]
        l_body = l_template + f"\n\nRegards,\nTeam Support"
        data.append({"text": l_body, "label": "legitimate"})
        
    df = pd.DataFrame(data)
    # Shuffle dataset
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    return df

def save_sample_eml_files():
    """Generates a few sample .eml, .txt files for manual testing."""
    sample_dir = os.path.join(DATASET_DIR, "sample_emails")
    os.makedirs(sample_dir, exist_ok=True)
    
    # Phishing Sample EML
    phish_eml = """From: "Microsoft Security Alert" <suspicious-login@micros0ft-secure.com>
To: "User" <user@example.com>
Subject: URGENT: Confirm account security activity now!
Date: Wed, 22 Jul 2026 10:42:00 +0000
Content-Type: text/plain; charset="utf-8"

Dear User,

We noticed a suspicious login attempt to your Microsoft Account from IP Address 192.168.1.199.
If you did not make this login, please verify your identity immediately to prevent block:

http://verification-portal-microsoft-secure.cc/verify

If you ignore this email, your account will be deleted permanently.

Thanks,
Microsoft Support Team
"""
    
    # Legitimate Sample EML
    legit_eml = """From: "Sarah Jenkins" <sjenkins@company.com>
To: "User" <user@example.com>
Subject: Project Kickoff Meeting Agenda
Date: Wed, 22 Jul 2026 09:15:00 +0000
Content-Type: text/plain; charset="utf-8"

Hi Team,

Looking forward to our project kickoff tomorrow. Please find the agenda outline:
1. Team introductions (10 mins)
2. Project scope and timeline review (20 mins)
3. Architecture walkthrough (30 mins)
4. Next steps & QA (15 mins)

Please review the attached project board link: https://github.com/company/project/projects/1

Best regards,
Sarah Jenkins
Product Manager
"""

    with open(os.path.join(sample_dir, "phishing_sample.eml"), "w", encoding="utf-8") as f:
        f.write(phish_eml)
        
    with open(os.path.join(sample_dir, "legitimate_sample.eml"), "w", encoding="utf-8") as f:
        f.write(legit_eml)
        
    # Phishing TXT Sample
    with open(os.path.join(sample_dir, "phishing_text_sample.txt"), "w", encoding="utf-8") as f:
        f.write("Subject: Payment Past Due! Avoid Late Penalty Fees\nYour invoice #9234 is past due. Click here http://payment-gateway-overdue.com to pay $45.99 now.")

    print(f"Sample EML/TXT files saved to: {sample_dir}")

def main():
    os.makedirs(DATASET_DIR, exist_ok=True)
    df = generate_synthetic_data(num_samples_per_class=120)
    df.to_csv(CSV_PATH, index=False)
    print(f"Dataset successfully created and saved to {CSV_PATH}")
    print(f"Total samples: {len(df)} ({df['label'].value_counts().to_dict()})")
    
    save_sample_eml_files()

if __name__ == "__main__":
    main()
