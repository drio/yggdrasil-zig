const std = @import("std");

pub const Tun = struct {
    fd: i32,
    name: []const u8,

    const IFF_TUN: u16 = 0x0001;
    const IFF_NO_PI: u16 = 0x1000;
    const TUNSETIFF: c_ulong = 0x400454ca;

    // ifreq structure for ioctl
    const ifreq = extern struct {
        ifr_name: [16]u8,
        ifr_flags: u16,
        _padding: [22]u8 = std.mem.zeroes([22]u8),
    };

    pub fn init(name: []const u8) !Tun {
        const file = std.fs.openFileAbsolute("/dev/net/tun", .{
            .mode = .read_write,
        }) catch |err| switch (err) {
            error.FileNotFound => {
                //std.debug.print("TUN device not found. Make sure TUN/TAP support is enabled.\n", .{});
                return err;
            },
            error.AccessDenied => {
                //std.debug.print("Permission denied. Try running as root.\n", .{});
                return err;
            },
            else => return err,
        };
        const fd = file.handle;

        // Prepare the ifreq mem chunk
        var ifr = std.mem.zeroes(ifreq);

        // Copy interface name (ensure null termination)
        const copy_len = @min(name.len, ifr.ifr_name.len - 1);
        @memcpy(ifr.ifr_name[0..copy_len], name[0..copy_len]);

        // Set flags for TUN device without packet info
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

        // Configure the device
        const result = std.os.linux.ioctl(fd, TUNSETIFF, @intFromPtr(&ifr));
        if (result != 0) {
            std.posix.close(fd);
            // TODO: get error value
            std.debug.print("Failed to configure TUN device. \n", .{});
            return error.IoctlFailed;
        }

        //std.debug.print("TUN device '{}' created successfully\n", .{name});

        return Tun{
            .fd = fd,
            .name = name,
        };
    }

    fn setIP(self: *Tun, ip_addr: []const u8, netmask: []const u8) !void {
        const allocator = std.heap.page_allocator;

        const ip_with_mask = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ ip_addr, netmask });
        defer allocator.free(ip_with_mask);

        const result = std.process.Child.run(.{
            .allocator = allocator,
            .argv = &[_][]const u8{ "ip", "addr", "add", try std.fmt.allocPrint(allocator, "{s}/{s}", .{ ip_addr, netmask }), "dev", self.name },
        }) catch |err| {
            std.debug.print("Failed to set IP address: {}\n", .{err});
            return err;
        };
        defer allocator.free(result.stdout);
        defer allocator.free(result.stderr);

        if (result.term.Exited != 0) {
            //std.debug.print("Failed to set IP address. Exit code: {}\n", .{result.term.Exited});
            //std.debug.print("stderr: {s}\n", .{result.stderr});
            return error.IPSetupFailed;
        }

        //std.debug.print("IP address {s}/{s} set on {s}\n", .{ ip_addr, netmask, self.name });
    }

    fn bringUp(self: *Tun) !void {
        const allocator = std.heap.page_allocator;

        const result = std.process.Child.run(.{
            .allocator = allocator,
            .argv = &[_][]const u8{ "ip", "link", "set", self.name, "up" },
        }) catch |err| {
            //std.debug.print("Failed to bring interface up: {}\n", .{err});
            return err;
        };
        defer allocator.free(result.stdout); // Add this
        defer allocator.free(result.stderr); // Add this

        if (result.term.Exited != 0) {
            // std.debug.print("Failed to bring interface up. Exit code: {}\n", .{result.term.Exited});
            // std.debug.print("stderr: {s}\n", .{result.stderr});
            return error.InterfaceUpFailed;
        }

        // std.debug.print("Interface {s} brought up\n", .{self.name});
    }

    pub fn configure(self: *Tun, ip_addr: []const u8, netmask: []const u8) !void {
        try self.setIP(ip_addr, netmask);
        try self.bringUp();
    }

    pub fn deinit(self: *Tun) void {
        std.posix.close(self.fd);
        //std.debug.print("TUN device '{s}' closed\n", .{self.name});
    }

    fn readPacket(self: *Tun, buffer: []u8) !usize {
        return std.posix.read(self.fd, buffer);
    }

    fn writePacket(self: *Tun, data: []const u8) !usize {
        return std.posix.write(self.fd, data);
    }

    pub fn runPacketLoop(self: *Tun) !void {
        var buf: [1504]u8 = undefined;

        //std.debug.print("Starting packet capture loop on '{s}'\n", .{self.name});

        while (true) {
            const n = self.readPacket(&buf) catch |err| {
                std.debug.print("Error reading packet: {}\n", .{err});
                continue;
            };

            //std.debug.print("Received {} bytes\n", .{n});

            // Basic IPv4 header parsing
            if (n < 20) {
                //std.debug.print("Packet too short to be IPv4\n", .{});
                continue;
            }

            const version = buf[0] >> 4;
            if (version != 4) {
                //std.debug.print("Not an IPv4 packet (version={s})\n", .{version});
                continue;
            }

            const src_ip = buf[12..16];
            const dst_ip = buf[16..20];
            const protocol = buf[9];

            std.debug.print(
                "IPv4 Packet: {}.{}.{}.{} -> {}.{}.{}.{}, proto: {} ({s})\n",
                .{
                    src_ip[0], src_ip[1],              src_ip[2], src_ip[3],
                    dst_ip[0], dst_ip[1],              dst_ip[2], dst_ip[3],
                    protocol,  protocolName(protocol),
                },
            );

            // Optional: Echo packet back to sender
            // _ = self.writePacket(buf[0..n]) catch |err| {
            //     std.debug.print("Error writing packet: {}\n", .{err});
            // };
        }
    }

    fn protocolName(protocol: u8) []const u8 {
        return switch (protocol) {
            1 => "ICMP",
            6 => "TCP",
            17 => "UDP",
            else => "Unknown",
        };
    }
};

// Usage example:
pub fn main() !void {
    var tun_dev = Tun.init("tun0") catch |err| {
        std.debug.print("Failed to create TUN device: {}\n", .{err});
        return;
    };
    defer tun_dev.deinit();

    // Run the packet capture loop
    try tun_dev.runPacketLoop();
}
