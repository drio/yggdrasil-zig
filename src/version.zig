// This logic captures how to encode and decode the handshake process
// to connect to the yggdrasil network via another node
//
// Wire format:
// Header: [4:"meta"][2:payload_length]
// Payload: [metadata_entries...][64:ed25519_signature]
// Each entry: [2:opcode][2:length][length:data]

const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const Allocator = std.mem.Allocator;
const Ed25519 = crypto.sign.Ed25519;
const testing = std.testing;

// Protocol version constants
pub const PROTOCOL_VERSION_MAJOR: u16 = 0;
pub const PROTOCOL_VERSION_MINOR: u16 = 5;

// Ed25519 key and signature sizes
pub const ED25519_PUBLIC_KEY_SIZE = 32;
pub const ED25519_PRIVATE_KEY_SIZE = 64;
pub const ED25519_SIGNATURE_SIZE = 64;

// Metadata field types
pub const MetaField = enum(u16) {
    version_major = 0,
    version_minor = 1,
    public_key = 2,
    priority = 3,
};

// Custom error types
pub const HandshakeError = error{
    InvalidPreamble,
    InvalidLength,
    InvalidPassword,
    HashFailure,
    IncorrectPassword,
    OutOfMemory,
    InvalidInput,
};

pub const VersionMetadata = struct {
    const Self = @This();

    major_ver: u16,
    minor_ver: u16,
    public_key: [ED25519_PUBLIC_KEY_SIZE]u8,
    priority: u8,

    // Create base metadata with correct version numbers
    pub fn init() Self {
        return Self{
            .major_ver = PROTOCOL_VERSION_MAJOR,
            .minor_ver = PROTOCOL_VERSION_MINOR,
            .public_key = [_]u8{0} ** ED25519_PUBLIC_KEY_SIZE,
            .priority = 0,
        };
    }

    // encode the payload for the handshake
    // the original go implementation uses passhword for the hash. We will use nil for now
    pub fn encode(self: *Self, allocator: Allocator, private_key: Ed25519.SecretKey, password: ?[]const u8) ![]u8 {
        var buffer = std.ArrayList(u8).init(allocator);
        defer buffer.deinit();

        // meta + reserve space for the size of this byte chunk
        try buffer.appendSlice("meta");
        try buffer.appendSlice(&[_]u8{ 0, 0 });

        // TODO: DRY this
        // major version
        const field_type = mem.nativeTo(u16, @intFromEnum(MetaField.version_major), .big);
        try buffer.appendSlice(&mem.toBytes(field_type));
        const field_length = mem.nativeTo(u16, 2, .big);
        try buffer.appendSlice(&mem.toBytes(field_length));
        const major_ver = mem.nativeTo(u16, self.major_ver, .big);
        try buffer.appendSlice(&mem.toBytes(major_ver));

        // minor version
        const minor_field_type = mem.nativeTo(u16, @intFromEnum(MetaField.version_minor), .big);
        try buffer.appendSlice(&mem.toBytes(minor_field_type));
        const minor_field_length = mem.nativeTo(u16, 2, .big);
        try buffer.appendSlice(&mem.toBytes(minor_field_length));
        const minor_ver = mem.nativeTo(u16, self.minor_ver, .big);
        try buffer.appendSlice(&mem.toBytes(minor_ver));

        // public key
        const public_key_type = mem.nativeTo(u16, @intFromEnum(MetaField.public_key), .big);
        try buffer.appendSlice(&mem.toBytes(public_key_type));
        const public_key_field_length = mem.nativeTo(u16, ED25519_PUBLIC_KEY_SIZE, .big);
        try buffer.appendSlice(&mem.toBytes(public_key_field_length));
        try buffer.appendSlice(&self.public_key);

        // priority
        const priority_field_type = mem.nativeTo(u16, @intFromEnum(MetaField.priority), .big);
        try buffer.appendSlice(&mem.toBytes(priority_field_type));
        const priority_field_length = mem.nativeTo(u16, 1, .big);
        try buffer.appendSlice(&mem.toBytes(priority_field_length));
        try buffer.appendSlice(&[_]u8{self.priority});

        // Create BLAKE2b hash of public key with password as key
        var hasher = if (password) |pwd|
            crypto.hash.blake2.Blake2b512.init(.{ .key = pwd }) // pwd is []const u8
        else
            crypto.hash.blake2.Blake2b512.init(.{}); // password was null

        // Signature
        // 1. Hash the public key
        hasher.update(&self.public_key);
        var hash: [64]u8 = undefined;
        hasher.final(&hash);
        // 2. Sign the hash with Ed25519
        const key_pair = try Ed25519.KeyPair.fromSecretKey(private_key);
        const signature = try key_pair.sign(&hash, null);
        // 3. Append signature to buffer
        try buffer.appendSlice(&signature.toBytes());

        // Fill in the length field before returning
        const remaining_length = @as(u16, @intCast(buffer.items.len - 6));
        mem.writeInt(u16, buffer.items[4..6], remaining_length, .big);

        // free the arraylist and return a new chunk of memory with our bytes
        return buffer.toOwnedSlice();
    }

    // decode these bytes and set the metadata
    pub fn decode(self: *Self, data: []const u8, password: ?[]const u8) !void {
        if (data.len < 6) return error.InsufficientData;

        // Let's check the header
        const bh = data[0..6];
        const meta = [4]u8{ 'm', 'e', 't', 'a' };
        if (!std.mem.eql(u8, bh[0..4], &meta)) {
            return error.HandshakeInvalidPreamble;
        }

        // Now the magic number that tells us how many bytes for the metadata + signature
        const hl = std.mem.readInt(u16, bh[4..6], .big);
        // At least it should be bigger than the signature
        // NOTE: in the go library, this constant is available. Should we send a PR?
        if (hl < ED25519_SIGNATURE_SIZE) {
            return error.HandshakeInvalidLength;
        }

        // Skip header, get the rest: metadata + signature
        const bs_full = data[6 .. 6 + hl];

        // Metadata
        const bs = bs_full[0 .. bs_full.len - ED25519_SIGNATURE_SIZE];
        // Signature
        const sig = bs_full[bs_full.len - ED25519_SIGNATURE_SIZE ..];

        // Each entry
        // [2 bytes: opcode][2 bytes: length][length bytes: value]
        var bs_remaining = bs;
        while (bs_remaining.len >= 4) {
            const op = std.mem.readInt(u16, bs_remaining[0..2], .big);

            const op_enum = std.meta.intToEnum(MetaField, op) catch |err| {
                std.debug.print("Failed to convert opcode {} to enum: {}\n", .{ op, err });
                return error.InvalidMetaDataEntry;
            };
            const oplen = std.mem.readInt(u16, bs_remaining[2..4], .big);

            bs_remaining = bs_remaining[4..]; // point to the actual entry data

            if (bs_remaining.len < oplen) {
                break;
            }

            switch (op_enum) {
                MetaField.version_major => {
                    self.major_ver = std.mem.readInt(u16, bs_remaining[0..2], .big);
                },
                MetaField.version_minor => {
                    self.minor_ver = std.mem.readInt(u16, bs_remaining[0..2], .big);
                },
                MetaField.public_key => {
                    @memcpy(&self.public_key, bs_remaining[0..ED25519_PUBLIC_KEY_SIZE]);
                },
                MetaField.priority => {
                    self.priority = bs_remaining[0];
                },
            }

            bs_remaining = bs_remaining[oplen..]; // next entry
        }

        // Signature next
        // 1. Create BLAKE2b hasher (with or without password)
        var hasher = if (password) |pwd|
            std.crypto.hash.blake2.Blake2b512.init(.{ .key = pwd })
        else
            std.crypto.hash.blake2.Blake2b512.init(.{});

        // 2. Hash the public key
        hasher.update(&self.public_key);
        var hash: [64]u8 = undefined;
        hasher.final(&hash);

        // 3. Now, verify that the public was signed with the private key (the sender owns the private key)
        const public_key = Ed25519.PublicKey.fromBytes(self.public_key) catch {
            return error.InvalidPublicKey;
        };

        const signature = Ed25519.Signature.fromBytes(sig[0..64].*);

        // Simple verification - this is what you want
        signature.verify(&hash, public_key) catch {
            return error.SignatureVerifiactionFailure;
        };
    }
};

const t_allocator = testing.allocator;

// Test to make sure logic works (or fails) correctly depending on the password param
test "version password auth" {
    const TestCase = struct {
        password1: ?[]const u8, // The password on node 1
        password2: ?[]const u8, // The password on node 2
        allowed: bool, // Should the connection have been allowed?
    };

    const test_cases = [_]TestCase{
        .{ .password1 = null, .password2 = null, .allowed = true }, // Allow: No passwords (both null)
        .{ .password1 = null, .password2 = "", .allowed = true }, // Allow: No passwords (mixed null and empty)
        .{ .password1 = null, .password2 = "foo", .allowed = false }, // Reject: One node has password, other doesn't
        .{ .password1 = "foo", .password2 = "", .allowed = false }, // Reject: One node has password, other doesn't
        .{ .password1 = "foo", .password2 = "foo", .allowed = true }, // Allow: Same password
        .{ .password1 = "foo", .password2 = "bar", .allowed = false }, // Reject: Different passwords
    };

    for (test_cases) |tt| {
        // Generate key pair for node 1
        var seed: [32]u8 = undefined;
        std.crypto.random.bytes(&seed);
        const key_pair = Ed25519.KeyPair.generate();

        // Create metadata for node 1
        var metadata1 = VersionMetadata{
            .public_key = key_pair.public_key.bytes,
            .major_ver = 1,
            .minor_ver = 0,
            .priority = 128,
        };

        // Convert optional passwords to slices

        // Generate over the wire data for node1
        const encoded = metadata1.encode(t_allocator, key_pair.secret_key, tt.password1) catch |err| {
            std.debug.panic("Node 1 failed to encode metadata: {}", .{err});
        };
        defer t_allocator.free(encoded);

        // We  are now in node2 and we want to decode the over the wire data received from node1
        var decoded = VersionMetadata{
            .public_key = undefined,
            .major_ver = 0,
            .minor_ver = 0,
            .priority = 0,
        };

        const decode_result = decoded.decode(encoded, tt.password2);
        const allowed = if (decode_result) true else |_| false;

        if (allowed != tt.allowed) {
            if (decode_result) |_| {
                std.debug.print("Test failed: password1='{?s}', password2='{?s}', expected={}, got={} (decode succeeded)\n", .{ tt.password1, tt.password2, tt.allowed, allowed });
            } else |err| {
                std.debug.print("Test failed: password1='{?s}', password2='{?s}', expected={}, got={} (decode failed with error: {})\n", .{ tt.password1, tt.password2, tt.allowed, allowed, err });
            }
        }
        try testing.expectEqual(tt.allowed, allowed);
    }
}

// Helper test to verify basic functionality
test "version metadata round trip" {
    const key_pair = Ed25519.KeyPair.generate();

    var original = VersionMetadata{
        .public_key = key_pair.public_key.bytes,
        .major_ver = 42,
        .minor_ver = 13,
        .priority = 200,
    };

    const password = "test_password";

    const encoded = try original.encode(t_allocator, key_pair.secret_key, password);
    defer t_allocator.free(encoded);

    // Decode
    var decoded = VersionMetadata{
        .public_key = undefined,
        .major_ver = 0,
        .minor_ver = 0,
        .priority = 0,
    };

    try decoded.decode(encoded, password);

    // Verify all fields match
    try testing.expectEqualSlices(u8, &original.public_key, &decoded.public_key);
    try testing.expectEqual(original.major_ver, decoded.major_ver);
    try testing.expectEqual(original.minor_ver, decoded.minor_ver);
    try testing.expectEqual(original.priority, decoded.priority);
}
