const std = @import("std");
const Ed25519 = std.crypto.sign.Ed25519;
const base64 = std.base64;

// 1. generate Ed25519 key generate and load
// 2. IPv6 address derivation (look at yggdrasil code)
// 3. hex encoding of the keys
pub fn main() !void {
    std.debug.print("start here!\n", .{});

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const key_pair = Ed25519.KeyPair.generate();
    const pub_bytes = key_pair.public_key.toBytes();
    const encoded_len = base64.standard.Encoder.calcSize(pub_bytes.len);

    const encoded = try allocator.alloc(u8, encoded_len);
    defer allocator.free(encoded);

    const result = base64.standard.Encoder.encode(encoded, &pub_bytes);

    std.debug.print("Original: {s}\n", .{pub_bytes});
    std.debug.print("Base64:   {s}\n", .{result});
}
