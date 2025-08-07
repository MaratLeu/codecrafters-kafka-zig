const std = @import("std");
const net = std.net;
const posix = std.posix;

const HeaderV0 = packed struct {correlation_id: u32};

const ResponseMessage = packed struct {
    message_size: i32,
    headers: HeaderV0,
};

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
    
    const response = ResponseMessage {
        .message_size = 0,
        .headers = .{
            .correlation_id = 7
        }
    };
    
    try writer.writeStructEndian(response, .big);
}
