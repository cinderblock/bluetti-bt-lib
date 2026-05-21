from .FieldName import FieldName


class DerivedBoolField:
    """A boolean field derived from a numeric sensor field (not read from a register)."""

    address = 0

    def __init__(self, name: FieldName, source: FieldName, above: float = 0):
        self.name = name.value
        self.source = source.value
        self.above = above
