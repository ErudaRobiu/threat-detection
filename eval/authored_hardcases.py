#!/usr/bin/env python3
"""
eval/authored_hardcases.py — authored legit-urgent emails to fill the categories
the SpamAssassin corpus (2002) genuinely lacks: modern account-security alerts,
modern transactional/delivery notices, and internal-business deadlines.

RULES THESE FOLLOW (from the handoff, non-negotiable):
  - Written to IMITATE real legit-urgent mail in length, tone and structure.
  - NOT written to score low, and NOT curated by score. Each carries label 0
    (legitimate) regardless of what A/H it comes back with. If one scores 0.9 it
    STAYS label 0 — that is an honest hard case, not a reason to edit or drop it.
  - Full email form (From / Subject / body with a real, clean brand domain and a
    link to that same domain) so the rule engine reads real structure: a clean
    registrable domain -> low R, urgent body -> high A, i.e. the flip zone where
    the agreement gate is supposed to suppress a false positive.

`synthetic: true`, `source: "authored"`. The examiner-visible risk is exactly this
authored legit class; it is kept as small as the real gaps require and every item
is disclosed as authored.
"""

# category, from_line, subject, body (with a real clean domain + link to it)
AUTHORED = [
    # ---- security-urgency (modern account-security alerts) ------------------
    ("security-urgency", "Chase Online <no-reply@chase.com>",
     "New sign-in to your Chase account",
     "We noticed a new sign-in to your Chase account from a device we don't "
     "recognise (Windows, Chrome) near Dallas, TX. If this was you, no action is "
     "needed. If you don't recognise it, review your recent activity and secure "
     "your account now at https://www.chase.com/security. For your protection we "
     "will never ask for your password or one-time code by email."),
    ("security-urgency", "Apple <no_reply@apple.com>",
     "Your Apple ID was used to sign in to iCloud",
     "Your Apple ID (r****@icloud.com) was used to sign in to iCloud on a new "
     "iPhone. Date: today. If this was you, you can ignore this email. If this was "
     "not you, your account may be at risk — change your password immediately at "
     "https://appleid.apple.com and remove any devices you don't recognise."),
    ("security-urgency", "Google <no-reply@accounts.google.com>",
     "Security alert: new sign-in on Windows",
     "Your Google Account was just signed in to on a new Windows device. You're "
     "getting this email to make sure it was you. If you recognise this activity "
     "you don't need to do anything. If not, we'll help you secure your account — "
     "check activity at https://myaccount.google.com/notifications."),
    ("security-urgency", "GitHub <noreply@github.com>",
     "[GitHub] A new SSH key was added to your account",
     "Hi, a new SSH key was added to your account. If this was you, there's "
     "nothing else you need to do. If you did not add this key, someone may have "
     "access to your account — remove it and review your security log now at "
     "https://github.com/settings/keys."),
    ("security-urgency", "Santander <alerts@santander.co.uk>",
     "Card transaction declined — please confirm it was you",
     "We declined a card transaction of £240.00 at an online retailer because it "
     "looked unusual for your account. If this was you, you can approve it in the "
     "app. If it wasn't, your card may be compromised — please review it right "
     "away at https://www.santander.co.uk. We will never ask for your PIN or full "
     "passcode by email."),

    # ---- transactional-urgency (delivery / order / invoice) -----------------
    ("transactional-urgency", "Amazon.co.uk <ship-confirm@amazon.co.uk>",
     "Your parcel is arriving today — action may be needed",
     "Your order #204-5589217 is out for delivery and arriving today by 9pm. If "
     "no one is home our driver will attempt to leave it in a safe place. To change "
     "delivery instructions or reschedule before the driver arrives, manage your "
     "order at https://www.amazon.co.uk/your-orders."),
    ("transactional-urgency", "DPD <noreply@dpd.co.uk>",
     "We missed you — reschedule your delivery",
     "We tried to deliver your parcel today but no one was available to receive "
     "it. Your parcel will be returned to the depot if we can't complete delivery "
     "within 3 days. Choose a new delivery date or a pickup point now at "
     "https://www.dpd.co.uk/reschedule using your tracking reference."),
    ("transactional-urgency", "British Gas <noreply@britishgas.co.uk>",
     "Your bill is ready and payment is due soon",
     "Your latest energy bill of £128.44 is now available. Payment is due by the "
     "28th. To avoid a late-payment charge, please make sure your Direct Debit is "
     "set up or pay online at https://www.britishgas.co.uk/account. If you've "
     "already paid, thank you and please ignore this reminder."),
    ("transactional-urgency", "Netflix <info@netflix.com>",
     "Your payment didn't go through",
     "We're having trouble with your current payment method, so your membership "
     "will be put on hold unless we can process payment. To keep watching without "
     "interruption, update your billing details at https://www.netflix.com/account "
     "before your next billing date."),
    ("transactional-urgency", "Companies House <noreply@companieshouse.gov.uk>",
     "Confirmation statement due — file to avoid penalties",
     "Our records show your company's confirmation statement is due for filing "
     "within 14 days. Late filing can lead to penalties and the company being "
     "struck off the register. File online at https://www.gov.uk/file-your-"
     "confirmation-statement to stay compliant."),

    # ---- internal-business (deadlines from your own org) --------------------
    ("internal-business", "Payroll <payroll@acme-corp.com>",
     "Timesheet cutoff is 5pm TODAY",
     "Reminder: the payroll cutoff is 5pm TODAY. If your timesheet is not "
     "submitted and approved by then, it will roll into next month's pay run and "
     "you will not be paid for this period. There are no exceptions. Submit now at "
     "https://acme-corp.com/timesheet."),
    ("internal-business", "IT Service Desk <itsupport@acme-corp.com>",
     "Mandatory password reset before Friday",
     "As part of our security policy all staff must reset their network password "
     "before 5pm Friday. Accounts that have not been updated will be locked and "
     "will require an in-person visit to the service desk to restore. Reset yours "
     "now at https://acme-corp.com/password."),
    ("internal-business", "HR <hr@acme-corp.com>",
     "Benefits enrolment closes tomorrow",
     "Open enrolment for next year's health and pension benefits closes tomorrow "
     "at midnight. If you do not make your selections in time you will keep your "
     "current elections and cannot change them until next year. Review and confirm "
     "your choices at https://acme-corp.com/benefits."),
    ("internal-business", "Facilities <facilities@acme-corp.com>",
     "Office access cards deactivate Monday — collect your new one",
     "All current building access cards will be deactivated at 6am Monday as part "
     "of the security upgrade. Collect your replacement card from reception before "
     "then or you will not be able to enter the building. Details and collection "
     "times: https://acme-corp.com/facilities."),

    # ---- marketing-urgency (a couple, to complement the mined real ones) ----
    ("marketing-urgency", "ASOS <news@asos.com>",
     "Your basket is about to expire — 20% off ends tonight",
     "The items in your basket are selling fast and we can't hold them much "
     "longer. Your 20% off code ENDS AT MIDNIGHT tonight — use code TREAT20 at "
     "checkout before it's gone. Shop your saved items now at "
     "https://www.asos.com. You're receiving this because you subscribed; "
     "unsubscribe any time."),
    ("marketing-urgency", "Trainline <no-reply@thetrainline.com>",
     "Last chance: advance fares for the bank holiday selling out",
     "Advance tickets for the bank holiday weekend are almost gone and prices go "
     "up as they sell out. Book now to lock in the cheapest fare before it "
     "disappears at https://www.thetrainline.com. Prices shown were correct at "
     "time of sending and change with availability."),
]


def authored_items():
    """Yield (content, category) for each authored legit-urgent email."""
    for category, frm, subject, body in AUTHORED:
        content = f"From: {frm}\nSubject: {subject}\n\n{body}"
        yield content, category
