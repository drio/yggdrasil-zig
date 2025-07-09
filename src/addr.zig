const std = @import("std");
const t = std.testing;
const Ed25519 = std.crypto.sign.Ed25519;

// Address type - 128-bit address = 16 bytes
const Address = struct {
    bytes: [16]u8,

    // is the address valid?
    pub fn is_valid(self: Address) bool {
        const prefix = getPrefix();
        for (0..prefix.len) |i| {
            if (self.bytes[i] != prefix[i]) return false;
        }
        return true;
    }
};

test "addr:is_valid" {
    var a = Address{ .bytes = std.mem.zeroes([16]u8) };
    try t.expect(a.is_valid() == false);

    a.bytes[0] = 0x03;
    try t.expect(a.is_valid() == false);

    a.bytes[0] = 0x02;
    try t.expect(a.is_valid() == true);
}

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
pub fn addrForKey(public_key: Ed25519.PublicKey) Address {
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
            const bit_idx: u3 = @intCast(i);
            // get each bit for the byte in buf we are working on
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

            // Now we have to store the remaining bits

            // Add the current bit to bits
            bits = (bits << 1) | bit;
            n_bits += 1;

            // If we have a full byte add it to temp and reset
            // so we can continue working on the first bit of
            // the next byte
            if (n_bits == 8) {
                temp[temp_len] = bits;
                temp_len += 1;
                n_bits = 0;
                bits = 0;
            }
        }
    }

    // Prepare the address
    // Prefix is a hardcoded 0x02 byte (as coded in the yggdrasil canonical implementation)
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

    return addr;
}

test "addr_for_key" {
    const public_key = try Ed25519.PublicKey.fromBytes([32]u8{
        189, 186, 207, 216, 34,  64,  222, 61, 205, 18,  57,  36, 203, 181, 82,  86,
        251, 141, 171, 8,   170, 152, 227, 5,  82,  138, 184, 79, 65,  158, 110, 251,
    });

    const expected_address = Address{ .bytes = [16]u8{
        2, 0, 132, 138, 96, 79, 187, 126, 67, 132, 101, 219, 141, 182, 104, 149,
    } };

    const addr = addrForKey(public_key);

    try t.expect(std.mem.eql(u8, &expected_address.bytes, &addr.bytes));
}
