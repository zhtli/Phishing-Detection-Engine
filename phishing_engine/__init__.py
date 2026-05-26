import logging

__version__ = "0.1.0"

# Library best practice: attach a no-op handler so importing the package never emits a
# "No handlers could be found" warning. Entry points call
# ``phishing_engine.core.logging_setup.configure_logging`` to install a real handler.
logging.getLogger(__name__).addHandler(logging.NullHandler())
