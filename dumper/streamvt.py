"""BinaryStream virtual method table (Itanium layout, slot 0/1 = dtors).
Order verified against the behaviour of each slot in 1.26.52 and against
Endstone's binary_stream.h declaration order."""
WRITE = {
    0x18: "bool", 0x20: "u8", 0x28: "i8", 0x30: "u16", 0x38: "i16",
    0x40: "u32", 0x48: "i32be", 0x50: "i32", 0x58: "u64", 0x60: "i64",
    0x68: "varuint32", 0x70: "varuint64", 0x78: "varint32", 0x80: "varint64",
    0x88: "f64", 0x90: "f32", 0x98: "fixedfloat", 0xa0: "normfloat",
    0xa8: "string", 0xb0: "if", 0xb8: "conditional", 0xc0: "branch",
    0xc8: "branch", 0xd0: "typeBegin", 0xd8: "typeEnd", 0xe0: "enum",
    0xe8: "array",
}
