const std = @import("std");
const base64 = std.base64;
const Allocator = std.mem.Allocator;
const process = std.process;
const Ed25519 = std.crypto.sign.Ed25519;

const addr = @import("addr.zig");

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

    // const keypair = Ed25519.KeyPair.generate();

    const keypair = createKeyPairFromEnv(allocator) catch |err| {
        std.debug.print("Failed to create keypair: {}\n", .{err});
        return;
    };
    std.debug.print("Ed25519 KeyPair loaded\n", .{});
    try printKey(keypair, allocator);

    const ip_addr = addr.addrForKey(keypair.public_key);
    std.debug.print("addr: ", .{});
    for (0..8) |i| {
        const group = (@as(u16, ip_addr.bytes[i * 2]) << 8) | ip_addr.bytes[i * 2 + 1];
        std.debug.print("{x:0>4}", .{group});
        if (i < 7) std.debug.print(":", .{});
    }
    std.debug.print("\n", .{});
}
