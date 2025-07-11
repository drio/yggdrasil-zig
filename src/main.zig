const std = @import("std");
const base64 = std.base64;
const Allocator = std.mem.Allocator;
const Ed25519 = std.crypto.sign.Ed25519;

const addr = @import("addr.zig");
const core = @import("core.zig");
const tun = @import("tun.zig");

// 1. generate Ed25519 key generate and load
// 2. hex encoding of the keys
// 3. IPv6 address derivation (look at yggdrasil code)
// 4. create tun device (set ipv6 address)
// 5. associate my ipv6 address to the tun device.
// 6. Do the handshake with G.
//  a. method to prepare structure.
//  b. write code to send handshake
//  c. read response.
// 7. read(tun): send them over the tcp connection to G.
// 8. read(tcp connection with G): write them to the tun device.
// Milestone: At this point I should have a functioning Yggdrasil leaf node.

pub fn main() !void {
    std.debug.print("start here!\n", .{});

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // const keypair = Ed25519.KeyPair.generate();

    const keypair = core.createKeyPairFromEnv(allocator) catch |err| {
        std.debug.print("Failed to create keypair: {}\n", .{err});
        return;
    };
    std.debug.print("Ed25519 KeyPair loaded\n", .{});
    try core.printKey(keypair, allocator);

    const ip_addr = addr.addrForKey(keypair.public_key);
    std.debug.print("addr: ", .{});
    for (0..8) |i| {
        const group = (@as(u16, ip_addr.bytes[i * 2]) << 8) | ip_addr.bytes[i * 2 + 1];
        std.debug.print("{x:0>4}", .{group});
        if (i < 7) std.debug.print(":", .{});
    }
    std.debug.print("\n", .{});
    std.debug.print("Is valid?: {} \n", .{ip_addr.is_valid()});

    var tun_dev = try tun.Tun.init("tun0");
    defer tun_dev.deinit();
    try tun_dev.configure("192.168.50.1", "24");
    try tun_dev.runPacketLoop();
}
