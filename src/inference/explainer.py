from reasoning.hypothesis import Hypothesis

EVIDENCE_DESCRIPTIONS = {
    "sender_domain": {
        "title": "Sender domain",
        "rationale": "The sender's domain was evaluated against the expected source."
    },
    "spf_result": {
        "title": "SPF authentication",
        "rationale": "SPF verifies whether the sending server is authorized."
    },
    "dkim_result": {
        "title": "DKIM authentication",
        "rationale": "DKIM verifies the integrity of the email."
    },
    "dmarc_result": {
        "title": "DMARC authentication",
        "rationale": "DMARC checks domain alignment and authentication."
    },
    "domain_alignment": {
        "title": "Domain alignment",
        "rationale": "Reply-To and From domains were compared."
    },
    "url": {
        "title": "Embedded URL",
        "rationale": "URLs were inspected for suspicious characteristics."
    },
    "attachment": {
        "title": "Attachment",
        "rationale": "Attachments were analyzed for potential risks."
    }
}

ASSESSMENTS = {
    "legitimate": {
        "risk": "LOW",
        "summary": "Most available evidence supports that the email is legitimate."
    },
    "phishing": {
        "risk": "HIGH",
        "summary": "Several indicators suggest the email may be malicious."
    },
    "spam": {
        "risk": "MEDIUM",
        "summary": "The email appears unsolicited or potentially unwanted."
    },
    "unknown": {
        "risk": "UNKNOWN",
        "summary": "There is insufficient evidence to classify this email confidently."
    }
}

class ExplanationGenerator:

    def _get_explanation(self, evidence):
        if evidence.evidence_type in EVIDENCE_DESCRIPTIONS:
            desc = EVIDENCE_DESCRIPTIONS[evidence.evidence_type]
            return f"{desc['title']}: {evidence.value}\n    {desc['rationale']}"
            
        return f"{evidence.evidence_type} = {evidence.value}"

    def generate(self, hypothesis: Hypothesis) -> str:
        lines = []

        lines.append(f"Classification: {hypothesis.name}")
        lines.append(f"Confidence: {hypothesis.confidence:.2f}")
        lines.append("")

        lines.append("Supporting Evidence:")

        if hypothesis.supporting:
            for evidence in hypothesis.supporting:
                explanation = self._get_explanation(evidence)
                lines.append(f"  ✔ {explanation}")
        else:
            lines.append("  None")

        lines.append("")

        lines.append("Contradictory Evidence:")

        if hypothesis.conflicting:
            for evidence in hypothesis.conflicting:
                explanation = self._get_explanation(evidence)
                lines.append(f"  ⚠ {explanation}")
        else:
            lines.append("  None")

        lines.append("")
        lines.append("Overall Assessment")
        lines.append("")

        if hypothesis.confidence >= 0.8:
            likelihood = "most likely"
        elif hypothesis.confidence >= 0.5:
            likelihood = "possibly"
        else:
            likelihood = "unlikely to be"

        display_name = hypothesis.display_name or hypothesis.name.lower()
        lines.append(f"Overall, this email is {likelihood} a {display_name}.")
        lines.append("")

        assessment = ASSESSMENTS.get(hypothesis.category, ASSESSMENTS["unknown"])
        lines.append(assessment["summary"])
        lines.append("")
        lines.append(f"Risk: {assessment['risk']}")

        return "\n".join(lines)