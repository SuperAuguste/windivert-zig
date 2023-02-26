const wd = @import("windivert");
const std = @import("std");

// GOTO http://info.cern.ch/

pub fn main() anyerror!void {
    var divert = try wd.WinDivert.open("tcp.SrcPort == 80", .network, 405, @intToEnum(wd.bindings.Flags, 0));
    defer divert.close();

    var buffer: [64_000]u8 = undefined;
    while (true) {
        var result = try divert.receive(&buffer);

        _ = std.mem.replace(u8, result.buffer, "website", "jomomma", result.buffer);
        _ = std.mem.replace(u8, result.buffer, "Web", "Joe", result.buffer);
        _ = std.mem.replace(u8, result.buffer, "web", "joe", result.buffer);

        _ = try divert.send(result.buffer, result.address);
    }
}
