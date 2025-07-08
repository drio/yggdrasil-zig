const std = @import("std");
const Ed25519 = std.crypto.sign.Ed25519;
const base64 = std.base64;
const Allocator = std.mem.Allocator;
const process = std.process;

// Address type - 128-bit address = 16 bytes
const Address = struct {
    bytes: [16]u8,
};

// In the yggdrasil go code, the prefix is harcoded to 0x02
fn getPrefix() [1]u8 {
    return [_]u8{0x02};
}

// Given a ed25519 public key return a IPv6 address that matches the
// yggdrasil network spec (16 bytes; 128 bits)
// Examples:
// key: 111011010...
// leading ones: 3
// final address/output: [0x02][3][11010...][zeros] (16 bytes; 128 bits)
// Notice how we skip the first byte (zero) after 1
fn addrForKey(public_key: Ed25519.PublicKey) ?*Address {
    var buf: [public_key.bytes.len]u8 = undefined;
    @memcpy(buf[0..], public_key.bytes[0..]);

    // iterate over the pointers to each byte in buf
    // On each byte of the buffer save the Bitwise NOT
    for (&buf) |*byte| {
        // dereference the pointer and assign the inverter value of each byte
        byte.* = ~byte.*;
    }

    // Step 4: Process bits and build address components
    var temp: [32]u8 = undefined; // Fixed-size buffer, max 32 bytes
    var temp_len: usize = 0; // Track how many bytes we've written

    var done: bool = false;
    var ones: u8 = 0;
    var bits: u8 = 0;
    var n_bits: u8 = 0;

    for (0..buf.len) |byte_idx| { // each byte in buf
        for (0..8) |i| {
            // get each bit for the byte in buf we are working on
            const bit_idx: u3 = @intCast(i);
            const bit = (buf[byte_idx] >> (7 - bit_idx)) & 1;

            // Count leading 1s
            if (!done and bit != 0) {
                ones += 1;
                continue;
            }

            // Skip the first 0 bit after leading 1s
            if (!done and bit == 0) {
                done = true;
                continue;
            }

            // apped the current bit to bits
            bits = (bits << 1) | @as(u8, bit);
            n_bits += 1;

            // If we have a full byte add it to temp and reset
            if (n_bits == 8) {
                temp[temp_len] = bits;
                temp_len += 1;
                n_bits = 0;
                bits = 0;
            }
        }
    }

    const prefix = getPrefix();
    var addr = Address{ .bytes = undefined };

    // Copy prefix to start of address
    @memcpy(addr.bytes[0..prefix.len], prefix[0..]);

    // Set the ones count after the prefix
    addr.bytes[prefix.len] = ones;

    // Calculate how much space is left
    const remaining_space = addr.bytes.len - (prefix.len + 1);
    const bytes_to_copy = @min(temp_len, remaining_space);

    // Copy only what fits
    @memcpy(addr.bytes[prefix.len + 1 .. prefix.len + 1 + bytes_to_copy], temp[0..bytes_to_copy]);

    return &addr;
}

// Helper function to convert bytes to base64
fn bytesToBase64(bytes: []const u8, allocator: Allocator) ![]const u8 {
    const encoded_len = base64.standard.Encoder.calcSize(bytes.len);
    const encoded = try allocator.alloc(u8, encoded_len);
    const result = base64.standard.Encoder.encode(encoded, bytes);
    return result; // Caller owns this memory
}

fn printKey(key_pair: Ed25519.KeyPair, allocator: Allocator) !void {
    // Public key
    {
        const pub_bytes = key_pair.public_key.toBytes();
        const pub_b64 = try bytesToBase64(&pub_bytes, allocator);
        defer allocator.free(pub_b64);
        std.debug.print("Base64 pub: {s}...\n", .{pub_b64[0..10]});
    }

    // Private Key
    {
        const pri_bytes = key_pair.secret_key.toBytes();
        const pri_b64 = try bytesToBase64(&pri_bytes, allocator);
        defer allocator.free(pri_b64);
        std.debug.print("Base64 pri: {s}...\n", .{pri_b64[0..10]});
    }
}

fn getEnvVar(allocator: std.mem.Allocator, name: []const u8) ![]u8 {
    if (std.process.getEnvVarOwned(allocator, name)) |val| {
        return val;
    } else |err| switch (err) {
        error.EnvironmentVariableNotFound => {
            std.debug.print("{s} not found\n", .{name});
            return err;
        },
        else => return err,
    }
}

fn createKeyPairFromEnv(allocator: std.mem.Allocator) !std.crypto.sign.Ed25519.KeyPair {
    // Get both environment variables
    const pub_key_env = getEnvVar(allocator, "ED25519_PUBLIC_KEY") catch |err| {
        return switch (err) {
            error.EnvironmentVariableNotFound => error.PublicKeyNotFound,
            else => err,
        };
    };
    defer allocator.free(pub_key_env);

    const secret_key_env = getEnvVar(allocator, "ED25519_SECRET_KEY") catch |err| {
        return switch (err) {
            error.EnvironmentVariableNotFound => error.SecretKeyNotFound,
            else => err,
        };
    };
    defer allocator.free(secret_key_env);

    // Convert hex strings to bytes
    // you cannot leave a variable unassigned in zig, set them to undefined
    // N bytes of garbage, no need to zero it
    var public_key: [32]u8 = undefined;
    var secret_key: [64]u8 = undefined;

    std.base64.standard.Decoder.decode(&public_key, pub_key_env) catch return error.InvalidPublicKeyFormat;
    std.base64.standard.Decoder.decode(&secret_key, secret_key_env) catch return error.InvalidSecretKeyFormat;

    // Create KeyPair
    return std.crypto.sign.Ed25519.KeyPair{
        .public_key = std.crypto.sign.Ed25519.PublicKey.fromBytes(public_key) catch return error.InvalidPublicKey,
        .secret_key = std.crypto.sign.Ed25519.SecretKey.fromBytes(secret_key) catch return error.InvalidSecretKey,
    };
}

// 1. generate Ed25519 key generate and load
// 2. hex encoding of the keys
// 3. IPv6 address derivation (look at yggdrasil code)
pub fn main() !void {
    std.debug.print("start here!\n", .{});

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const keypair = Ed25519.KeyPair.generate();

    // const keypair = createKeyPairFromEnv(allocator) catch |err| {
    //     std.debug.print("Failed to create keypair: {}\n", .{err});
    //     return;
    // };
    //std.debug.print("Ed25519 KeyPair loaded\n", .{});
    //

    try printKey(keypair, allocator);
    if (addrForKey(keypair.public_key)) |addr| {
        std.debug.print("addr: ", .{});
        for (0..8) |i| {
            const group = (@as(u16, addr.bytes[i * 2]) << 8) | addr.bytes[i * 2 + 1];
            std.debug.print("{x:0>4}", .{group});
            if (i < 7) std.debug.print(":", .{});
        }
        std.debug.print("\n", .{});
    } else {
        return error.InvalidKey;
    }
}
