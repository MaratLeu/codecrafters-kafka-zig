const std = @import("std");
const posix = std.posix;
const net = std.net;
const Thread = std.Thread;

const APIVersion = packed struct {
    api_key: u16,
    min_supported_apiversion: u16,
    max_supported_apiversion: u16,
    tag_buffer: u8 = 0x00,
};

const APIVersionsArray = packed struct {
    array_length: u8,
    version_1: APIVersion,
    version_2: APIVersion, 
    version_3: APIVersion,
};

const ResponseBody = packed struct {
    error_code: u16,
    versions_array: APIVersionsArray,
    throttle_time: u32,
    tag_buffer: u8 = 0x00,
};

const APIVersionsResponse = packed struct {
    message_size: u32,
    headers: u32, 
    body: ResponseBody,
};

const CLIENT_ID = struct {
    length: u16,
    contents_ptr: []u8,
};

const HeaderV0 = struct {
    request_api_key: u16,
    request_api_version: u16,
    correlation_id: u32,
    client_id: CLIENT_ID,
    tag_buffer: u8 = 0x00,
};

const CompactString = struct {
    length: u8,
    contents_ptr: []u8,
};

const RequestBody = struct {
    client_id: CompactString,
    client_software_version: CompactString,
    tag_buffer: u8 = 0x00,
};

const APIVersionsRequest = struct {
    message_size: u32,
    headers: HeaderV0,
    body: RequestBody,

    fn parse_request (reader: anytype) !APIVersionsRequest {
        const mess_size = try reader.readInt(u32, .big);
        
        //parse headers
        const api_key = try reader.readInt(u16, .big);
        const api_version = try reader.readInt(u16, .big);
        const corr_id = try reader.readInt(u32, .big);
        
        const head_client_id_length = try reader.readInt(u16, .big);
        const head_client_id_bytes = try std.heap.page_allocator.alloc(u8, head_client_id_length); 
        _ = try reader.readAtLeast(head_client_id_bytes, head_client_id_length);

        const headers_client_id = CLIENT_ID {
            .length = head_client_id_length,
            .contents_ptr = head_client_id_bytes,
        };

        const head_tag = try reader.readByte();

        const headers_ = HeaderV0 {
            .request_api_key = api_key,
            .request_api_version = api_version,
            .correlation_id = corr_id,
            .client_id = headers_client_id, 
            .tag_buffer = head_tag,
        };

        // parse body
        const body_client_id_length = try reader.readByte();
        const body_client_id_bytes = try std.heap.page_allocator.alloc(u8, body_client_id_length - 1);
        _ = try reader.readAtLeast(body_client_id_bytes, body_client_id_length - 1);

        const body_client_id = CompactString {
            .length = body_client_id_length,
            .contents_ptr = body_client_id_bytes,
        };

        const body_client_softversion = try reader.readByte();
        const body_client_softversion_bytes = try std.heap.page_allocator.alloc(u8, body_client_softversion - 1);
        _ = try reader.readAtLeast(body_client_softversion_bytes, body_client_softversion - 1);

        const body_softversion = CompactString {
            .length = body_client_softversion,
            .contents_ptr = body_client_softversion_bytes,
        };

        const body_tag = try reader.readByte();

        const body_ = RequestBody {
            .client_id = body_client_id,
            .client_software_version = body_softversion,
            .tag_buffer = body_tag,
        };

        return APIVersionsRequest {
            .message_size = mess_size,
            .headers = headers_,
            .body = body_,     
        };     
    }
};

fn is_valid_api_version(api_version: u16) bool {
    return api_version >= 0 and api_version <= 4;
}

fn writeResponse(writer: anytype, response: APIVersionsResponse) !void {
    // Write message_size (u32)
    try writer.writeInt(u32, response.message_size, .big);

    // Write correlation_id (u32)
    try writer.writeInt(u32, response.headers, .big);

    // Write error_code (u16)
    try writer.writeInt(u16, response.body.error_code, .big);

    // Write array_length (u8)
    try writer.writeByte(response.body.versions_array.array_length);

    // Write each APIVersion
    const versions = [_]APIVersion{
        response.body.versions_array.version_1,
        response.body.versions_array.version_2,
        response.body.versions_array.version_3,
    };

    for (versions) |version| {
        try writer.writeInt(u16, version.api_key, .big);
        try writer.writeInt(u16, version.min_supported_apiversion, .big);
        try writer.writeInt(u16, version.max_supported_apiversion, .big);
        try writer.writeByte(version.tag_buffer);
    }

    // Write throttle_time (u32)
    try writer.writeInt(u32, response.body.throttle_time, .big);

    // Write tag_buffer (u8)
    try writer.writeByte(response.body.tag_buffer);
}

fn Context(comptime WriterType: type) type {
    return struct {
        socket: net.Stream,
        writer: WriterType,

        pub fn respond(self: *@This(), msg: []const u8) !void {
            try self.writer.writeAll(msg);
        }
    };
}

fn listen_client(comptime WriterType: type, ctx: Context(WriterType)) !void {
    defer ctx.socket.close();

    while (true) {
        var buffer: [1024]u8 = undefined;

        const bytes_read = posix.read(ctx.socket.handle, buffer[0..]) catch |err| {
            std.debug.print("Read error: {}\n", .{err});
            break;
        };

        if (bytes_read == 0) {
            std.debug.print("Client disconnected\n", .{});
            break;
        }

        var stream_ = std.io.fixedBufferStream(buffer[0..bytes_read]);
        const reader = stream_.reader();

        const request = APIVersionsRequest.parse_request(reader) catch |err| {
            std.debug.print("Parse error: {}\n", .{err});
            break;
        };

        const is_valid_version = is_valid_api_version(request.headers.request_api_version);

        const response = APIVersionsResponse {
            .message_size = (@bitSizeOf(APIVersionsResponse) >> 3) - @sizeOf(u32),
            .headers = request.headers.correlation_id,
            .body = ResponseBody {
                .error_code = if (is_valid_version) 0 else 35,
                .versions_array = APIVersionsArray {
                    .array_length = 4,
                    .version_1 = APIVersion { .api_key = 1, .min_supported_apiversion = 0, .max_supported_apiversion = 17, .tag_buffer = 0x00 },
                    .version_2 = APIVersion { .api_key = 18, .min_supported_apiversion = 0, .max_supported_apiversion = 4, .tag_buffer = 0x00 },
                    .version_3 = APIVersion { .api_key = 75, .min_supported_apiversion = 0, .max_supported_apiversion = 0, .tag_buffer = 0x00 },
                },
                .throttle_time = 768,
                .tag_buffer = 0x00,
            },
        };

        try writeResponse(ctx.writer, response);
    }
}

pub fn main() !void {
    const sock_fd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
    defer posix.close(sock_fd);

    const addr = net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 9092);
    const c: c_int = 1;
    try posix.setsockopt(sock_fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&c));
    try posix.bind(sock_fd, &addr.any, addr.getOsSockLen());
    try posix.listen(sock_fd, 128);

    std.debug.print("Server listening on 127.0.0.1:9092\n", .{});

    while (true) {
        var client_addr: posix.sockaddr = undefined;
        var client_addr_len: posix.socklen_t = @sizeOf(posix.sockaddr);

        const client_fd = posix.accept(sock_fd, &client_addr, &client_addr_len, posix.SOCK.CLOEXEC) catch |err| {
            std.debug.print("Accept error: {}\n", .{err});
            continue;
        };

        const stream = net.Stream { .handle = client_fd };
        const writer = stream.writer();

        const WriterType = @TypeOf(writer);
        const ContextType = Context(WriterType);

        const ctx = ContextType {
            .socket = stream,
            .writer = writer,
        };

        const thread = Thread.spawn(.{}, listen_client, .{WriterType, ctx}) catch |err| {
            std.debug.print("Thread spawn error: {}\n", .{err});
            stream.close();
            continue;
        };

        thread.detach();
    }
}
