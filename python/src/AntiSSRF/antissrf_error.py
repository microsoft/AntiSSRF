# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

class AntiSSRFError(Exception):
    """Custom exception for AntiSSRF violations."""
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)
