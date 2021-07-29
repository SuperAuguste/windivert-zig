const std = @import("std");
const Handle = windows.HANDLE;
const windows = std.os.windows;

pub const Layer = enum(c_int) {
    network = 0,
    network_forward = 1,
    flow = 2,
    socket = 3,
    reflect = 4,
    _,
};

pub const Flags = enum(u64) {
    sniff = 0x0001,
    drop = 0x0002,
    /// aka read_only
    recv_only = 0x0004,
    /// aka write_only
    send_only = 0x0008,
    no_install = 0x0010,
    fragments = 0x0020,
    _,
};

pub const NetworkLayerData = extern struct {
    interface_index: u32,
    sub_interface_index: u32,
};

pub const FlowLayerData = extern struct {
    endpoint_id: u64,
    parent_endpoint_id: u64,
    process_id: u32,
    local_addr: [4]u32,
    remote_addr: [4]u32,
    local_port: u16,
    remote_port: u16,
    protocol: u8,
};

pub const SocketLayerData = extern struct {
    endpoint_id: u64,
    parent_endpoint_id: u64,
    process_id: u32,
    local_addr: [4]u32,
    remote_addr: [4]u32,
    local_port: u16,
    remote_port: u16,
    protocol: u8,
};

pub const ReflectLayerData = extern struct {
    timestamp: i64,
    process_id: u32,
    layer: Layer,
    flags: Flags,
    priority: i16,
};

pub const LayerData = extern union {
    network: NetworkLayerData,
    flow: FlowLayerData,
    socket: SocketLayerData,
    reflect: ReflectLayerData,
    reserved: [64]u8,
};

pub const Address = packed struct {
    timestamp: i64,
    layer: u8,
    event: u8,

    is_sniffed: bool,
    is_outbound: bool,
    is_loopback: bool,
    is_impostor: bool,
    is_ipv6: bool,

    has_ip_checksum: bool,
    has_tcp_checksum: bool,
    has_udp_checksum: bool,

    reserved: u8,
    reserved2: u32,

    data: LayerData,

    pub fn getLayer(self: Address) Layer {
        return @intToEnum(Layer, self.layer);
    }
};

pub extern fn WinDivertOpen(filter: [*c]const u8, layer: Layer, priority: i16, flags: Flags) Handle;
pub extern fn WinDivertClose(handle: Handle) windows.BOOL;
pub extern fn WinDivertRecv(handle: Handle, pPacket: ?*c_void, packetLen: c_uint, pRecvLen: [*c]c_uint, pAddr: ?*Address) windows.BOOL;
pub extern fn WinDivertSend(handle: Handle, pPacket: ?*const c_void, packetLen: c_uint, pSendLen: [*c]c_uint, pAddr: ?*const Address) windows.BOOL;

pub const OpenError = error{
    DriverNotFound,
    LackOfPrivilege,
    InvalidParameter,
    InvalidDigitalSignature,
    IncompatibleDriver,
    DriverNotInstalled,
    DriverBlocked,
    BaseFilteringEngineDisabled,
    Unexpected,
};

pub fn open(filter: []const u8, layer: Layer, priority: i16, flags: Flags) OpenError!Handle {
    var handle = WinDivertOpen(filter.ptr, layer, priority, flags);
    if (handle == windows.INVALID_HANDLE_VALUE) switch (windows.kernel32.GetLastError()) {
        .FILE_NOT_FOUND => return error.DriverNotFound, // The driver files WinDivert32.sys or WinDivert64.sys were not found
        .ACCESS_DENIED => return error.LackOfPrivilege, // The calling application does not have Administrator privileges
        .INVALID_PARAMETER => return error.InvalidParameter, // This indicates an invalid packet filter string, layer, priority, or flags
        .INVALID_IMAGE_HASH => return error.InvalidDigitalSignature, // The WinDivert32.sys or WinDivert64.sys driver does not have a valid digital signature (https://reqrypt.org/windivert-doc.html#driver_signing)
        .DRIVER_FAILED_PRIOR_UNLOAD => return error.IncompatibleDriver, // An incompatible version of the WinDivert driver is currently loaded
        .SERVICE_DOES_NOT_EXIST => return error.DriverNotInstalled, // The handle was opened with the WINDIVERT_FLAG_NO_INSTALL flag and the WinDivert driver is not already installed
        .DRIVER_BLOCKED => return error.DriverBlocked, // Security software / driver incompatible VM
        .EPT_S_NOT_REGISTERED => return error.BaseFilteringEngineDisabled, // This error occurs when the Base Filtering Engine service has been disabled.
        else => |err| return windows.unexpectedError(err),
    };
    return handle;
}

pub fn close(handle: Handle) error{Unexpected}!void {
    if (WinDivertClose(handle) == 0)
        return windows.unexpectedError(windows.kernel32.GetLastError());
}

pub const ReceiveError = error{
    InsufficientBuffer,
    NoData,
    Unexpected,
};
pub const ReceiveResult = struct {
    len: c_uint,
    buffer: []u8,
    address: Address,
};

pub fn receive(handle: Handle, buffer: []u8) ReceiveError!ReceiveResult {
    var result: ReceiveResult = undefined;
    if (WinDivertRecv(handle, buffer.ptr, @intCast(c_uint, buffer.len), &result.len, &result.address) == 0) switch (windows.kernel32.GetLastError()) {
        .INSUFFICIENT_BUFFER => return error.InsufficientBuffer, // The captured packet is larger than the pPacket buffer
        .NO_DATA => return error.NoData, // The handle has been shutdown using WinDivertShutdown() and the packet queue is empty
        else => |err| return windows.unexpectedError(err),
    };
    result.buffer = buffer[0..result.len];
    return result;
}

pub const SendError = error{
    Unexpected,
};

pub fn send(handle: Handle, buffer: []u8, address: Address) SendError!c_uint {
    var bytes_sent: c_uint = 0;
    if (WinDivertSend(handle, buffer.ptr, @intCast(c_uint, buffer.len), &bytes_sent, &address) == 0) return windows.unexpectedError(windows.kernel32.GetLastError());
    return bytes_sent;
}
