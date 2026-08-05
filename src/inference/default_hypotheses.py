from reasoning.hypothesis import Hypothesis


def load_default_hypotheses():
    return [

        Hypothesis(
            name="Legitimate GitHub Notification",
            display_name="legitimate GitHub notification",
            category="legitimate",

            required=[
                ("sender_domain", "github.com"),
                ("spf_result", "pass"),
                ("dkim_result", "pass"),
                ("dmarc_result", "pass"),
            ],

            forbidden=[
                ("domain_alignment", False),
            ]
        ),

        Hypothesis(
            name="GitHub Phishing",
            display_name="GitHub phishing attempt",
            category="phishing",

            required=[
                ("sender_domain", "github.com"),
            ],

            forbidden=[
                ("spf_result", "pass"),
                ("dkim_result", "pass"),
                ("dmarc_result", "pass"),
            ]
        ),
    ]