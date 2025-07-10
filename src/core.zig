const std = @import("std");
const base64 = std.base64;
const Allocator = std.mem.Allocator;
const process = std.process;
const Ed25519 = std.crypto.sign.Ed25519;

// Helper function to convert bytes to base64
fn bytesToBase64(bytes: []const u8, allocator: Allocator) ![]const u8 {
    const encoded_len = base64.standard.Encoder.calcSize(bytes.len);
    const encoded = try allocator.alloc(u8, encoded_len);
    const result = base64.standard.Encoder.encode(encoded, bytes);
    return result; // Caller owns this memory
}

pub fn printKey(key_pair: Ed25519.KeyPair, allocator: Allocator) !void {
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

pub fn createKeyPairFromEnv(allocator: std.mem.Allocator) !std.crypto.sign.Ed25519.KeyPair {
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
