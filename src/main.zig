const std = @import("std");
const base64 = std.base64;
const Allocator = std.mem.Allocator;
const Ed25519 = std.crypto.sign.Ed25519;
const net = std.net;

const addr = @import("addr.zig");
const core = @import("core.zig");
const tun = @import("tun.zig");
const version = @import("version.zig");

// - [x] 1. generate Ed25519 key generate and load
// - [x] 2. hex encoding of the keys
// - [x] 3. IPv6 address derivation (look at yggdrasil code)
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
    addr.printIPv6(ip_addr);
    std.debug.print("Is valid?: {} \n", .{ip_addr.is_valid()});

    var tun_dev = try tun.Tun.init("tun0");
    defer tun_dev.deinit();
    // try tun_dev.configure("192.168.50.1", "24");
    try tun_dev.configure("0200:2cdc:a6eb:28ba:5497:0c62:a5c9:a8a8", "64");
    try tun_dev.runPacketLoop();

    // var metadata = version.VersionMetadata.init();
    // const handshake_bytes = try metadata.encode(allocator, keypair.secret_key, null);
    // defer allocator.free(handshake_bytes);
    // std.debug.print("Bytes: ", .{});
    // for (handshake_bytes) |b| std.debug.print("{X:0>2}", .{b});
    // std.debug.print("\n", .{});

    //const a = net.Address.initIp6(ip_addr.bytes, 0, 0, 0);
    //std.debug.print("--> {}", .{a});
}
