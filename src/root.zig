const std = @import("std");
const Ed25519 = std.crypto.sign.Ed25519;
const base64 = std.base64;
const Allocator = std.mem.Allocator;

// Helper function to convert bytes to base64
fn bytesToBase64(bytes: []const u8, allocator: Allocator) ![]const u8 {
    const encoded_len = base64.standard.Encoder.calcSize(bytes.len);
    const encoded = try allocator.alloc(u8, encoded_len);
    const result = base64.standard.Encoder.encode(encoded, bytes);
    return result; // Caller owns this memory
}

// 1. generate Ed25519 key generate and load
// 2. IPv6 address derivation (look at yggdrasil code)
// 3. hex encoding of the keys
pub fn main() !void {
    std.debug.print("start here!\n", .{});

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const key_pair = Ed25519.KeyPair.generate();

    // Public key
    {
        const pub_bytes = key_pair.public_key.toBytes();
        const pub_b64 = try bytesToBase64(&pub_bytes, allocator);
        defer allocator.free(pub_b64);
        std.debug.print("Base64 pub: {s}\n", .{pub_b64});
    }

    // Private Key
    {
        const pri_bytes = key_pair.secret_key.toBytes();
        const pri_b64 = try bytesToBase64(&pri_bytes, allocator);
        defer allocator.free(pri_b64);
        std.debug.print("Base64 pri: {s}\n", .{pri_b64});
    }
}
