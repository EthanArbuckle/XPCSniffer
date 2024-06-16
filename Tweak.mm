/*
 * XPCSniffer
 *
 * Created by EvilPenguin
 */

#include <Foundation/Foundation.h>
#include <dlfcn.h>
#include <time.h>
#include <pthread.h>
#include <syslog.h>

#include "libproc/libproc.h"
#include "xpc/xpc.h"
#include "substrate.h"

#define INSN_CALL 0x94000000, 0xFC000000

#pragma mark - variables

static dispatch_queue_t _xpcsniffer_queue = dispatch_queue_create("XPCSniffer",  DISPATCH_QUEUE_SERIAL);
static CFPropertyListRef (*__CFBinaryPlistCreate15)(const uint8_t *, uint64_t) = nil;
static CFTypeRef (*__CFXPCCreateCFObjectFromXPCObject)(xpc_object_t) = nil;

#pragma mark - functions

static uint64_t _xpcsniffer_real_signextend_64(uint64_t imm, uint8_t bit);
static uintptr_t *_xpcsniffer_step64(uint32_t *base, size_t length, uint8_t step_count, uint32_t what, uint32_t mask);
static NSString *_xpcsniffer_get_timestring(void);
static NSMutableDictionary *_xpcsniffer_dictionary(xpc_connection_t connection, xpc_object_t xpc_message);
static NSString *_xpcsniffer_connection_name(xpc_connection_t connection);
static NSString *_xpcsniffer_proc_name(int pid);
static int _xpcsniffer_bplist_type(const char *bytes, size_t length);
static id _xpcsniffer_parse_bplist(const char *bytes, size_t length, int type);
static CFMessagePortRef _xpcsniffer_get_remote_port(void);
static void _xpcsniffer_send_message_to_remote(const char *message);
static NSDictionary *_xpcsniffer_json_safe_dictionary(NSDictionary *dict);
static id _xpcsniffer_json_safe(id object);

#pragma mark - private

#ifdef DEBUG
    #define DLog(FORMAT, ...) syslog(LOG_ERR, "+[XPCSniffer] %s\n", [[NSString stringWithFormat:FORMAT, ##__VA_ARGS__] UTF8String]);
#else 
    #define DLog(...) (void)0
#endif

static uint64_t _xpcsniffer_real_signextend_64(uint64_t imm, uint8_t bit) {
    if ((imm >> bit) & 1) 
        return (-1LL << (bit + 1)) + imm;

    return imm;
}

static uintptr_t *_xpcsniffer_step64(uint32_t *base, size_t length, uint8_t step_count, uint32_t what, uint32_t mask) {
    uint32_t *start = (uint32_t *)base;
    uint32_t *end = start + length;
    uint8_t current_step_count = 0;

    while (start < end) {
        uint32_t operation = *start;
        if ((operation & mask) == what) {
            if (++current_step_count == step_count) {
                signed imm = (operation & 0x3ffffff) << 2;
                imm = _xpcsniffer_real_signextend_64(imm, 27);
                uintptr_t addr = reinterpret_cast<uintptr_t>(start) + imm;
                
                return (uintptr_t *)addr;
            }
        }
        start++;
    }

    return NULL;
}

static NSString *_xpcsniffer_get_timestring(void) {
    time_t now = time(NULL);
    char *timeString = ctime(&now);
    timeString[strlen(timeString) - 1] = '\0';

    return [NSString stringWithUTF8String:timeString];
}

static NSMutableDictionary *_xpcsniffer_dictionary(xpc_connection_t connection, xpc_object_t xpc_message) {
    NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
    dictionary[@"connection_time"] = _xpcsniffer_get_timestring();

    if (connection == NULL && xpc_message == NULL) {
        return dictionary;
    }

    if (connection) {
        dictionary[@"connection"] = _xpcsniffer_connection_name(connection);
    }

    if (xpc_message == NULL) {
        return dictionary;
    }

    // Check if the object is bplist17-formatted. If it is, and there's an XPC connection,
    // setup an NSXPCDecoder to decode the message
    if (xpc_get_type(xpc_message) == XPC_TYPE_DICTIONARY) {
        
        xpc_object_t root = xpc_dictionary_get_value(xpc_message, "root");
        if (root) {
            @try {
                Class _NSXPCDecoder = NSClassFromString(@"NSXPCDecoder");
                id decoder = [[_NSXPCDecoder alloc] init];

                if (connection) {
                    // The xpc connection supplies details about classes that may be needed to decode the message
                    [decoder performSelector:NSSelectorFromString(@"set_connection:") withObject:(__bridge id)connection];
                }

                [decoder performSelector:NSSelectorFromString(@"_startReadingFromXPCObject:") withObject:xpc_message];
                id decodedPlist = [decoder debugDescription];

                dictionary[@"xpc_message"] = decodedPlist;
                return dictionary;
            }
            @catch (NSException *exception) {
                DLog(@"Failed to decode rootb17 %@", exception);
            }
        }
    }

    // The object is not a bplist17 root (or at least not a valid one).
    // See if CoreFoundation can decode it
    id object = (__bridge id)__CFXPCCreateCFObjectFromXPCObject(xpc_message);
    if (object) {
        dictionary[@"xpc_message"] = object;
    }

    return dictionary;
}

static NSString *_xpcsniffer_connection_name(xpc_connection_t connection) {

    if (connection == NULL) {
        return @"?";
    }

    const char *name = xpc_connection_get_name(connection);
    if (name) {
        return @(name);
    }

    // Try for the PID if there's no name
    pid_t pid = xpc_connection_get_pid(connection);
    if (pid > 0) {
        return _xpcsniffer_proc_name(pid);
    }

    // Fallback to the pointer value
    return [NSString stringWithFormat:@"%p", connection];
}

static NSString *_xpcsniffer_proc_name(int pid) {
    static char buffer[2048];
    proc_name(pid, buffer, 2048);

    if (strlen(buffer) == 0) {
        buffer[0] = '?';
    }

    return @(buffer);
}

static NSString *_xpcsniffer_hex_string(const char *bytes, size_t length) {
    NSMutableString *hexString = [NSMutableString string];
    for (int i = 0; i < length; i++) [hexString appendFormat:@"%02x ", (unsigned char)bytes[i]];

    return hexString;
}

static int _xpcsniffer_bplist_type(const char *bytes, size_t length) {
    int type = -1;

    if (bytes && length >= 8) {
        if (memcmp(bytes, "bplist17", 8) == 0)      type = -1; // todo
        else if (memcmp(bytes, "bplist16", 8) == 0) type = 16;
        else if (memcmp(bytes, "bplist15", 8) == 0) type = 15;
        else if (memcmp(bytes, "bplist00", 8) == 0) type = 0;
    }

    return type;
}

static id _xpcsniffer_parse_bplist(const char *bytes, size_t length, int type) {
    id returnValue = nil;

    switch (type) {
        // bplist00
        case 0: {
            NSError *error = nil;    
            NSData *data = [NSData dataWithBytes:bytes length:length];
            returnValue = [NSPropertyListSerialization propertyListWithData:data options:0 format:nil error:&error];
            if (error || (returnValue == nil && data.length > 0)) {
                DLog(@"Failed to parse bplist00: %@ %@", error, data);
            }
            break;
        }   
        // bplist15
        case 15: {
            if (__CFBinaryPlistCreate15) {
                returnValue = (__bridge id)__CFBinaryPlistCreate15((const uint8_t *)bytes, length);
            }
            else {
                returnValue = _xpcsniffer_hex_string(bytes, length);
            }

            break;
        }
        // bplist16
        case 16:
            returnValue = _xpcsniffer_hex_string(bytes, length);
            break;

        default:
            break;
    }

    return returnValue;
}

static void _xpcsniffer_send_message_to_remote(const char *message) {

    size_t msglen = 0;
    if (message == NULL || (msglen = strlen(message)) == 0) {
        DLog(@"Refusing to send an empty message");
        return;
    }

    CFMessagePortRef remotePort = _xpcsniffer_get_remote_port();
    if (remotePort == NULL) {
        DLog(@"Failed to get remote port. Not sending anything");
        return;
    }

    CFDataRef data = CFDataCreate(NULL, (const UInt8 *)message, msglen);
    if (data == NULL) {
        DLog(@"Failed to build message data. Not sending anything");
        return;
    }

    SInt32 result = -1;
    int attempts = 0;
    while (attempts < 3) {

        result = CFMessagePortSendRequest(remotePort, 0xdeadbeef, data, 0, 0, NULL, NULL);
        if (result == kCFMessagePortSendTimeout || result == kCFMessagePortReceiveTimeout) {
            usleep(1000000);
            attempts++;
        }
        
        break;
    }
    CFRelease(data);

    if (result != kCFMessagePortSuccess) {
        DLog(@"Failed to send message after multiple attempts. Error: %d", result);
    }
}

id _xpcsniffer_json_safe(id object) {
    
    if (!object) {
        return @"NULL";
    }

    if ([object isKindOfClass:[NSDictionary class]]) {
        return _xpcsniffer_json_safe_dictionary(object);
    }
    else if ([object isKindOfClass:[NSArray class]]) {

        NSMutableArray *sanitizedArray = [NSMutableArray array];
        for (id item in object) {
            [sanitizedArray addObject:_xpcsniffer_json_safe(item)];
        }

        return sanitizedArray;
    }
    else if ([object isKindOfClass:[NSData class]]) {

        NSData *data = object;
        const char *bytes = (const char *)data.bytes;
        if (data.length == 0 || bytes == NULL) {
            return @"<empty>";
        }
        
        int type = _xpcsniffer_bplist_type(bytes, (size_t)data.length);
        if (type >= 0) {
            id plist = _xpcsniffer_parse_bplist(bytes, (size_t)data.length, type);
            return _xpcsniffer_json_safe(plist);
        }

        @try {
            CFPropertyListRef plist = __CFBinaryPlistCreate15((const uint8_t *)bytes, data.length);
            if (plist) {
                return _xpcsniffer_json_safe((__bridge id)plist);
            }
        }
        @catch (NSException *exception) {
            DLog(@"Exception when trying to decode bplist: %@", exception);
        }

        return [object base64EncodedStringWithOptions:0];
    }
    else if ([object isKindOfClass:NSClassFromString(@"__NSCFType")]) {
        return [object description];
    }
    else if ([object isKindOfClass:[NSDate class]] || [object isKindOfClass:NSClassFromString(@"__NSTaggedDate")]) {
        return [object description];
    }

    return object;
}

NSDictionary *_xpcsniffer_json_safe_dictionary(NSDictionary *inputDictionary) {
    NSMutableDictionary *sanitizedDictionary = [NSMutableDictionary dictionary];
    
    for (NSString *key in inputDictionary) {
        id value = inputDictionary[key];
        sanitizedDictionary[key] = _xpcsniffer_json_safe(value);
    }

    return sanitizedDictionary;
}

static void _xpcsniffer_log_to_file(NSDictionary *dictionary) {

    if (!dictionary || [dictionary valueForKey:@"xpc_message"] == nil) {
        return;
    }

    NSDictionary *jsonSafeDictionary = _xpcsniffer_json_safe_dictionary(dictionary);
    if (!jsonSafeDictionary) {
        return;
    }

    dispatch_async(_xpcsniffer_queue, ^{
        
        NSError *error = nil;
        NSData *jsonData = [NSJSONSerialization dataWithJSONObject:jsonSafeDictionary options:0 error:&error];
        if (error || !jsonData) {
            DLog(@"Error serializing JSON: %@", error);
            return;
        }

        NSString *message = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
        _xpcsniffer_send_message_to_remote([message UTF8String]);
    });
}

#pragma mark - xpc_connection_create

// xpc_connection_t xpc_connection_create(const char *name, dispatch_queue_t targetq);
__unused static xpc_connection_t (*orig_xpc_connection_create)(const char *name, dispatch_queue_t targetq);
__unused static xpc_connection_t new_xpc_connection_create(const char *name, dispatch_queue_t targetq) {

    xpc_connection_t returned = orig_xpc_connection_create(name, targetq);
    return returned;
}

#pragma mark - xpc_pipe_routine

// int xpc_pipe_routine(xpc_object_t pipe, xpc_object_t request, xpc_object_t *reply);
__unused static int (*orig_xpc_pipe_routine)(xpc_object_t pipe, xpc_object_t request, xpc_object_t *reply);
__unused static int new_xpc_pipe_routine (xpc_object_t pipe, xpc_object_t request, xpc_object_t *reply) {
    // Call orig
    int returnValue = orig_xpc_pipe_routine(pipe, request, reply);

    // Log
    NSMutableDictionary *logDictionary = _xpcsniffer_dictionary(pipe, request);
    logDictionary[@"pipe_desc"] = @(xpc_copy_description(pipe));

    if (*reply && __CFXPCCreateCFObjectFromXPCObject) {
        CFTypeRef replyObject = __CFXPCCreateCFObjectFromXPCObject(*reply);
        id sanitizedReply = _xpcsniffer_json_safe((__bridge id)replyObject);
        logDictionary[@"reply"] = sanitizedReply;
    }

    return returnValue;
}

#pragma mark - xpc_connection_send_message

// void xpc_connection_send_message(xpc_connection_t connection, xpc_object_t message);
__unused static void (*orig_xpc_connection_send_message)(xpc_connection_t connection, xpc_object_t message);
__unused static void new_xpc_connection_send_message(xpc_connection_t connection, xpc_object_t message) {
    NSMutableDictionary *logDictionary = _xpcsniffer_dictionary(connection, message);

    _xpcsniffer_log_to_file(logDictionary);

    orig_xpc_connection_send_message(connection, message);
}

#pragma mark - xpc_connection_send_message_with_reply

// void xpc_connection_send_message_with_reply(xpc_connection_t connection, xpc_object_t message, dispatch_queue_t replyq, xpc_handler_t handler);
__unused static void (*orig_xpc_connection_send_message_with_reply)(xpc_connection_t connection, xpc_object_t message, dispatch_queue_t replyq, xpc_handler_t handler);
__unused static void new_xpc_connection_send_message_with_reply(xpc_connection_t connection, xpc_object_t message, dispatch_queue_t replyq, xpc_handler_t handler) {
    NSMutableDictionary *logDictionary = _xpcsniffer_dictionary(connection, message);
    logDictionary[@"reply_queue"] = [NSString stringWithFormat:@"%p", replyq];
    _xpcsniffer_log_to_file(logDictionary);

    orig_xpc_connection_send_message_with_reply(connection, message, replyq, handler);
}

#pragma mark - xpc_connection_send_message_with_reply_sync

// xpc_object_t xpc_connection_send_message_with_reply_sync(xpc_connection_t connection, xpc_object_t message);
__unused static xpc_object_t (*orig_xpc_connection_send_message_with_reply_sync)(xpc_connection_t connection, xpc_object_t message);
__unused static xpc_object_t new_xpc_connection_send_message_with_reply_sync(xpc_connection_t connection, xpc_object_t message) {
    NSMutableDictionary *logDictionary = _xpcsniffer_dictionary(connection, message);
    
    _xpcsniffer_log_to_file(logDictionary);

    return orig_xpc_connection_send_message_with_reply_sync(connection, message);
}

static CFMessagePortRef _xpcsniffer_get_remote_port(void) {
    static CFMessagePortRef remotePort = NULL;
    if (remotePort == NULL) {
        
        FILE *fp = fopen("/tmp/xpcsniffer_message.port", "r");
        if (fp == NULL) {
            DLog(@"Failed to read port name from file");
            return NULL;
        }

        char port_name[256];
        if (fscanf(fp, "%255s", port_name) != 1) {
            DLog(@"Failed to read port name from file\n");
            fclose(fp);
            return NULL;
        }
        fclose(fp);

        CFStringRef cf_port_name = CFStringCreateWithCString(NULL, port_name, kCFStringEncodingUTF8);
        if (cf_port_name == NULL) {
            DLog(@"Failed to create CFString for port name");
            return NULL;
        }

        remotePort = CFMessagePortCreateRemote(kCFAllocatorDefault, cf_port_name);
        CFRelease(cf_port_name);
        if (remotePort == NULL) {
            DLog(@"Failed to create remote message port");
            return NULL;
        }

        SInt32 result = CFMessagePortSendRequest(remotePort, 0xf00dface, NULL, 0, 0, NULL, NULL);
        if (result != kCFMessagePortSuccess) {
            DLog(@"Failed to send a check-in message to the remote port, error: %d", result);
            CFRelease(remotePort);
            return NULL;
        }

        DLog(@"Created remote message port %p with name %s", remotePort, port_name);
    }

    return remotePort;
}

#pragma mark - ctor

%ctor {
    @autoreleasepool {     
        DLog(@"~~ Hooking ~~");
    
        if (_xpcsniffer_get_remote_port() == NULL) {
            DLog(@"Failed to setup the remote message port");
            return;
        }

        // CoreFoundation
        void *cf_handle = dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", RTLD_NOW);
        DLog(@"cf_handle: %p", cf_handle);

        // _CFXPCCreateCFObjectFromXPCMessage
        uint32_t *_CFXPCCreateCFObjectFromXPCMessage = (uint32_t *)dlsym(cf_handle, "_CFXPCCreateCFObjectFromXPCMessage");
        DLog(@"_CFXPCCreateCFObjectFromXPCMessage %p", _CFXPCCreateCFObjectFromXPCMessage);
        
        // __CFBinaryPlistCreate15
        __CFBinaryPlistCreate15 = (CFPropertyListRef(*)(const uint8_t *, uint64_t))_xpcsniffer_step64(_CFXPCCreateCFObjectFromXPCMessage, 64, 2, INSN_CALL);
        DLog(@"__CFBinaryPlistCreate15 %p", __CFBinaryPlistCreate15);

        // _CFXPCCreateCFObjectFromXPCObject
        __CFXPCCreateCFObjectFromXPCObject = (CFTypeRef (*)(xpc_object_t))dlsym(RTLD_DEFAULT, "_CFXPCCreateCFObjectFromXPCObject");
        DLog(@"__CFXPCCreateCFObjectFromXPCObject %p", __CFXPCCreateCFObjectFromXPCObject);

        // libxpc
        void *libxpc_handle = dlopen("/usr/lib/system/libxpc.dylib", RTLD_NOW);
        DLog(@"libxpc: %p", libxpc_handle);

        // xpc_connection_create
        void *xpc_connection_create = dlsym(libxpc_handle, "xpc_connection_create");
        if (xpc_connection_create) {
            DLog(@"xpc_connection_create %p", xpc_connection_create);
            MSHookFunction((void *)xpc_connection_create, (void *)new_xpc_connection_create, (void **)&orig_xpc_connection_create);
        }

        // xpc_pipe_routine
        void *xpc_pipe_routine = dlsym(libxpc_handle, "xpc_pipe_routine");
        if (xpc_pipe_routine) {
            DLog(@"xpc_pipe_routine %p", xpc_pipe_routine);
            MSHookFunction((void *)xpc_pipe_routine, (void *)new_xpc_pipe_routine, (void **)&orig_xpc_pipe_routine);
        }

        // xpc_connection_send_message
        void *xpc_connection_send_message = dlsym(libxpc_handle, "xpc_connection_send_message");
        if (xpc_connection_send_message) {
            DLog(@"xpc_connection_send_message %p", xpc_connection_send_message);
            MSHookFunction((void *)xpc_connection_send_message, (void *)new_xpc_connection_send_message, (void **)&orig_xpc_connection_send_message);
        }

        // xpc_connection_send_message_with_reply
        void *xpc_connection_send_message_with_reply = dlsym(libxpc_handle, "xpc_connection_send_message_with_reply");
        if (xpc_connection_send_message_with_reply) {
            DLog(@"xpc_connection_send_message_with_reply %p", xpc_connection_send_message_with_reply);
            MSHookFunction((void *)xpc_connection_send_message_with_reply, (void *)new_xpc_connection_send_message_with_reply, (void **)&orig_xpc_connection_send_message_with_reply);
        }

        // xpc_connection_send_message_with_reply_sync
        void *xpc_connection_send_message_with_reply_sync = dlsym(libxpc_handle, "xpc_connection_send_message_with_reply_sync");
        if (xpc_connection_send_message_with_reply_sync) {
            DLog(@"xpc_connection_send_message_with_reply_sync %p", xpc_connection_send_message_with_reply_sync);
            MSHookFunction((void *)xpc_connection_send_message_with_reply_sync, (void *)new_xpc_connection_send_message_with_reply_sync, (void **)&orig_xpc_connection_send_message_with_reply_sync);
        }

        DLog(@"~~ End Hooking ~~");
    }
}