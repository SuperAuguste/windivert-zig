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

pub const Address = extern struct {
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

const Protocol = enum(u8) {
    hopopt = 0x00,
    icmp = 0x01,
    igmp = 0x02,
    ggp = 0x03,
    ip_in_ip = 0x04,
    st = 0x05,
    tcp = 0x06,
    cbt = 0x07,
    egp = 0x08,
    igp = 0x09,
    bbn_rcc_mon = 0x0A,
    nvp_ii = 0x0B,
    pup = 0x0C,
    argus = 0x0D,
    emcon = 0x0E,
    xnet = 0x0F,
    chaos = 0x10,
    udp = 0x11,
    mux = 0x12,
    dcn_meas = 0x13,
    hmp = 0x14,
    prm = 0x15,
    xns_idp = 0x16,
    trunk_1 = 0x17,
    trunk_2 = 0x18,
    leaf_1 = 0x19,
    leaf_2 = 0x1A,
    rdp = 0x1B,
    irtp = 0x1C,
    iso_tp4 = 0x1D,
    netblt = 0x1E,
    mfe_nsp = 0x1F,
    merit_inp = 0x20,
    dccp = 0x21,
    @"3pc" = 0x22,
    idpr = 0x23,
    xtp = 0x24,
    ddp = 0x25,
    idpr_cmtp = 0x26,
    tppp = 0x27,
    il = 0x28,
    ipv6 = 0x29,
    sdrp = 0x2A,
    ipv6_route = 0x2B,
    ipv6_frag = 0x2C,
    idrp = 0x2D,
    rsvp = 0x2E,
    gre = 0x2F,
    dsr = 0x30,
    bna = 0x31,
    esp = 0x32,
    ah = 0x33,
    i_nlsp = 0x34,
    swipe = 0x35,
    narp = 0x36,
    mobile = 0x37,
    tlsp = 0x38,
    skip = 0x39,
    ipv6_icmp = 0x3A,
    ipv6_nonxt = 0x3B,
    ipv6_opts = 0x3C,
    any_host_internal_protocol = 0x3D,
    cftp = 0x3E,
    any_local_network = 0x3F,
    sat_expak = 0x40,
    kryptolan = 0x41,
    rvd = 0x42,
    ippc = 0x43,
    any_distributed_fs = 0x44,
    sat_mon = 0x45,
    visa = 0x46,
    ipcu = 0x47,
    cpnx = 0x48,
    cphb = 0x49,
    wsn = 0x4A,
    pvp = 0x4B,
    br_sat_mon = 0x4C,
    sun_nd = 0x4D,
    wb_mon = 0x4E,
    wb_expak = 0x4F,
    iso_ip = 0x50,
    vmtp = 0x51,
    secure_vmtp = 0x52,
    vines = 0x53,
    ttp_iptm = 0x54,
    nsfnet_igp = 0x55,
    dgp = 0x56,
    tcf = 0x57,
    eigrp = 0x58,
    ospf = 0x59,
    sprite_rpc = 0x5A,
    larp = 0x5B,
    mtp = 0x5C,
    ax_25 = 0x5D,
    os = 0x5E,
    micp = 0x5F,
    scc_sp = 0x60,
    etherip = 0x61,
    encap = 0x62,
    any_private_scheme = 0x63,
    gmtp = 0x64,
    ifmp = 0x65,
    pnni = 0x66,
    pim = 0x67,
    aris = 0x68,
    scps = 0x69,
    qnx = 0x6A,
    a_n = 0x6B,
    ipcomp = 0x6C,
    snp = 0x6D,
    compaq_peer = 0x6E,
    ipx_in_ip = 0x6F,
    vrrp = 0x70,
    pgm = 0x71,
    any_0_hop = 0x72,
    l2tp = 0x73,
    ddx = 0x74,
    iatp = 0x75,
    stp = 0x76,
    srp = 0x77,
    uti = 0x78,
    smp = 0x79,
    sm = 0x7A,
    ptp = 0x7B,
    is_is_over_ipv4 = 0x7C,
    fire = 0x7D,
    crtp = 0x7E,
    crudp = 0x7F,
    sscopmce = 0x80,
    iplt = 0x81,
    sps = 0x82,
    pipe = 0x83,
    sctp = 0x84,
    fc = 0x85,
    rsvp_e2e_ignore = 0x86,
    mobility_header = 0x87,
    udplite = 0x88,
    mpls_in_ip = 0x89,
    manet = 0x8A,
    hip = 0x8B,
    shim6 = 0x8C,
    wesp = 0x8D,
    rohc = 0x8E,
    ethernet = 0x8F,
    // unassigned = 0x90 - 0xFC,
    // use_for_experimentation_and_testing = 0xFD - 0xFE,
    reserved = 0xFF,
};

pub const IpHeader = extern struct {
    meta: packed struct(u8) {
        hdr_length: u4,
        version: u4,
    },
    tos: u8,
    length: u16,
    id: u16,
    frag_off0: u16,
    ttl: u8,
    protocol: Protocol,
    checksum: u16,
    src_addr: [4]u8,
    dst_addr: [4]u8,
};

pub const Ipv6Header = extern struct {
    meta: packed struct(u16) {
        traffic_class0: u4,
        version: u4,
        flow_label0: u4,
        traffic_class1: u4,
    },
    flow_label1: u16,
    length: u16,
    next_hdr: u8,
    hop_limit: u8,
    src_addr: [4]u32,
    dst_addr: [4]u32,
};

pub const TcpHeader = extern struct {
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    meta: packed struct(u8) {
        reserved1: u4,
        hdr_length: u4,
    },
    meta2: packed struct(u8) {
        fin: u1,
        syn: u1,
        rst: u1,
        psh: u1,
        ack: u1,
        urg: u1,
        reserved2: u2,
    },
    window: u16,
    checksum: u16,
    urg_ptr: u16,
};

pub const UdpHeader = extern struct {
    src_port: u16,
    dst_port: u16,
    length: u16,
    checksum: u16,
};

pub extern fn WinDivertOpen(filter: [*c]const u8, layer: Layer, priority: i16, flags: Flags) Handle;
pub extern fn WinDivertClose(handle: Handle) windows.BOOL;
pub extern fn WinDivertRecv(handle: Handle, pPacket: ?*anyopaque, packetLen: c_uint, pRecvLen: [*c]c_uint, pAddr: ?*Address) windows.BOOL;
pub extern fn WinDivertSend(handle: Handle, pPacket: ?*const anyopaque, packetLen: c_uint, pSendLen: [*c]c_uint, pAddr: ?*const Address) windows.BOOL;
pub extern fn WinDivertHelperParsePacket(
    pPacket: [*]const u8,
    packetLen: c_uint,
    ppIpHdr: *?*IpHeader,
    ppIpv6Hdr: *?*Ipv6Header,
    pProtocol: *Protocol,
    // TODO: Implement ICMP
    ppIcmpHdr: *?*anyopaque,
    ppIcmpv6Hdr: *?*anyopaque,
    ppTcpHdr: *?*TcpHeader,
    ppUdpHdr: *?*UdpHeader,
    ppData: *[*]const u8,
    pDataLen: *c_uint,
    ppNext: *?*anyopaque,
    pNextLen: *c_uint,
) windows.BOOL;

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

pub const ParsePacketError = error{
    Unknown,
};

pub const ParsedPacket = struct {
    ip_header: ?IpHeader,
    ipv6_header: ?Ipv6Header,
    protocol: Protocol,
    // TODO: ICMP
    tcp_header: ?TcpHeader,
    udp_header: ?UdpHeader,

    payload: []const u8,
};

fn fixEndianness(value: anytype) @TypeOf(value) {
    const T = @TypeOf(value);
    return switch (@typeInfo(T)) {
        .Int => std.mem.nativeToBig(T, value),
        .Struct => |s| {
            if (s.backing_integer != null) return value;

            var new: T = undefined;
            inline for (std.meta.fields(T)) |field| {
                @field(new, field.name) = fixEndianness(@field(value, field.name));
            }
            return new;
        },
        else => value,
    };
}

// TODO: Bridge endianness fixing and this remaining mutable and valid (parsePacketMutable?)
pub fn parsePacket(packet: []const u8) ParsePacketError!ParsedPacket {
    var ip_header: ?*IpHeader = undefined;
    var ipv6_header: ?*Ipv6Header = undefined;
    var protocol: Protocol = undefined;
    var icmp_header: ?*anyopaque = undefined;
    var icmpv6_header: ?*anyopaque = undefined;
    var tcp_header: ?*TcpHeader = undefined;
    var udp_header: ?*UdpHeader = undefined;
    var payload_ptr: [*]const u8 = undefined;
    var payload_len: c_uint = undefined;
    var pp_next: ?*anyopaque = undefined;
    var p_next_len: c_uint = undefined;

    if (WinDivertHelperParsePacket(
        packet.ptr,
        @intCast(c_uint, packet.len),
        &ip_header,
        &ipv6_header,
        &protocol,
        &icmp_header,
        &icmpv6_header,
        &tcp_header,
        &udp_header,
        &payload_ptr,
        &payload_len,
        &pp_next,
        &p_next_len,
    ) == 0) return error.Unknown;

    return .{
        .ip_header = if (ip_header) |s| fixEndianness(s.*) else null,
        .ipv6_header = if (ipv6_header) |s| fixEndianness(s.*) else null,
        .protocol = protocol,
        .tcp_header = if (tcp_header) |s| fixEndianness(s.*) else null,
        .udp_header = if (udp_header) |s| fixEndianness(s.*) else null,
        .payload = payload_ptr[0..@intCast(usize, payload_len)],
    };
}
