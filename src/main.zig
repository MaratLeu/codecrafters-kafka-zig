const std = @import("std");
const net = std.net;
const posix = std.posix;

const HeaderV0 = packed struct {
    request_api_key: i16,
    request_api_version: i16,
    correlation_id: i32,
};

const ResponseMessage = packed struct {
    message_size: i32,
    headers: i32, 
    error_code: i16,
};

const RequestMessage = packed struct {
    message_size: i32,
    headers: HeaderV0,

    fn parse(reader: anytype) !RequestMessage {
        return RequestMessage {
            .message_size = try reader.readInt(i32, .big),
            .headers = HeaderV0 {
                .request_api_key = try reader.readInt(i16, .big),
                .request_api_version = try reader.readInt(i16, .big),
                .correlation_id = try reader.readInt(i32, .big),
            } 
        };
    }
};

fn is_valid_api_version(api_version: i16) bool {
    return api_version >= 0 and api_version <= 4;
}

pub fn main() !void {
    const sock_fd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
    defer posix.close(sock_fd);

    const addr = net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 9092);
    const c: c_int = 1;
    try posix.setsockopt(sock_fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&c));
    try posix.bind(sock_fd, &addr.any, addr.getOsSockLen());
    try posix.listen(sock_fd, 1);

    // You can use print statements as follows for debugging, they'll be visible when running tests.
    std.debug.print("Logs from your program will appear here!\n", .{});

    var client_addr: posix.sockaddr = undefined;
    var client_addr_len: posix.socklen_t = @sizeOf(posix.sockaddr);
    const client_socket = try posix.accept(sock_fd, &client_addr, &client_addr_len, posix.SOCK.CLOEXEC);
    defer posix.close(client_socket); 

    const stream = std.net.Stream {.handle = client_socket}; 
    const writer = stream.writer();
    
    var buffer: [1024]u8 = undefined;
    _ = try posix.read(client_socket, buffer[0..]);
   
    var stream_ = std.io.fixedBufferStream(buffer[0..]);
    const reader = stream_.reader();
    const request = try RequestMessage.parse(reader);

    const is_valid_version = is_valid_api_version(request.headers.request_api_version);
    const response = ResponseMessage {
        .message_size = request.message_size,
        .headers = request.headers.correlation_id,
        .error_code = if (is_valid_version) 0 else 35,
    };
    
    try writer.writeStructEndian(response, .big);
}
