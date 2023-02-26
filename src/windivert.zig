const std = @import("std");
const Handle = windows.HANDLE;
const windows = std.os.windows;

pub const bindings = @import("bindings.zig");

pub const WinDivert = struct {
    const Self = @This();

    handle: Handle,

    pub fn open(filter: []const u8, layer: bindings.Layer, priority: i16, flags: bindings.Flags) bindings.OpenError!Self {
        return Self{
            .handle = try bindings.open(filter, layer, priority, flags),
        };
    }

    pub fn close(self: *Self) void {
        bindings.close(self.handle) catch {};
    }

    pub fn receive(self: *Self, buffer: []u8) bindings.ReceiveError!bindings.ReceiveResult {
        return bindings.receive(self.handle, buffer);
    }

    pub fn send(self: *Self, buffer: []u8, address: bindings.Address) bindings.SendError!c_uint {
        return bindings.send(self.handle, buffer, address);
    }
};

pub const parsePacket = bindings.parsePacket;
