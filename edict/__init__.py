"""Edict — what your domain declares.

An offline grader for the mail policy a domain publishes about itself: SPF,
DMARC, DKIM, MX and CAA, read straight out of pasted DNS records. It counts the
SPF lookup budget, derives a DKIM key's real size from the key material, and
grades the published policy A+ to F — without ever resolving a name, and without
ever claiming a domain cannot be spoofed.
"""

__version__ = "1.0.0"
__all__ = ["__version__"]
