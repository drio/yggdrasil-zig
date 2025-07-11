const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const Allocator = std.mem.Allocator;
const Ed25519 = crypto.sign.Ed25519;

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
    pub fn encode(self: *const Self, allocator: Allocator, private_key: Ed25519.SecretKey, password: ?[]const u8) ![]u8 {
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
        const public_key_field_length = mem.nativeTo(u16, 2, .big);
        try buffer.appendSlice(&mem.toBytes(public_key_field_length));
        try buffer.appendSlice(&private_key.publicKeyBytes());

        // priority
        const priority_field_type = mem.nativeTo(u16, @intFromEnum(MetaField.priority), .big);
        try buffer.appendSlice(&mem.toBytes(priority_field_type));
        const priority_field_length = mem.nativeTo(u16, 1, .big);
        try buffer.appendSlice(&mem.toBytes(priority_field_length));
        const priority_value = mem.nativeTo(u16, self.priority, .big);
        try buffer.appendSlice(&mem.toBytes(priority_value));

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
};
