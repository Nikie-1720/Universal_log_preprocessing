"""Reference entrypoint for the ULPF-Plugin-v1 contract.
The live registry uses configs/parsers/*.yaml; this package documents the
third-party plugin shape and can be adapted to a Python parser implementation.
"""
class ULPFPlugin:
    id = "replace-me"
    version = "1.0.0"

    def detect(self, event): raise NotImplementedError
    def parse(self, event): raise NotImplementedError
    def normalize(self, fields): raise NotImplementedError
    def validate(self, event): raise NotImplementedError
    def metadata(self): return {"contract": "ULPF-Plugin-v1"}
