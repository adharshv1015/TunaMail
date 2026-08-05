from abc import ABC, abstractmethod


class EvidenceCollector(ABC):
    """
    Base class for all email evidence collectors.
    """

    name = "base_collector"


    @abstractmethod
    def collect(self, email_data):
        """
        Extract evidence from email data.
        """
        pass