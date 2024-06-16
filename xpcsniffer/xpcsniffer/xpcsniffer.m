//
//  xpcsniffer.m
//  xpcsniffer
//
//  Created by Ethan Arbuckle on 6/15/24.
//

#import <Foundation/Foundation.h>
#import <mach-o/dyld_images.h>
#import <sys/sysctl.h>
#import <dlfcn.h>


extern kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t *address, mach_vm_size_t size, int flags);
extern kern_return_t mach_vm_protect(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection);
extern kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);


static void *make_sym_callable_data(void *ptr) {
    ptr = ptrauth_sign_unauthenticated(ptrauth_strip(ptr, ptrauth_key_process_independent_data), ptrauth_key_process_independent_data, 0);
    return ptr;
}


static void inject_dylib_into_task(task_t target_task, const char *dylib_path) {

    mach_vm_size_t stack_size = 0x4000;
    mach_port_insert_right(mach_task_self_, target_task, target_task, MACH_MSG_TYPE_COPY_SEND);
    
    mach_vm_address_t remote_stack;
    mach_vm_allocate(target_task, &remote_stack, stack_size, VM_FLAGS_ANYWHERE);
    mach_vm_protect(target_task, remote_stack, stack_size, 1, VM_PROT_READ | VM_PROT_WRITE);
    
    mach_vm_address_t remote_dylib_path_str;
    mach_vm_allocate(target_task, &remote_dylib_path_str, 0x100 + strlen(dylib_path) + 1, VM_FLAGS_ANYWHERE);
    mach_vm_write(target_task, 0x100 + remote_dylib_path_str, (vm_offset_t)dylib_path, (mach_msg_type_number_t)strlen(dylib_path) + 1);
    
    uint64_t *stack = malloc(stack_size);
    size_t sp = (stack_size / 8) - 2;
    
    mach_port_t remote_thread;
    if (thread_create(target_task, &remote_thread) != KERN_SUCCESS) {
        free(stack);
        printf("failed to create remote thread\n");
        return;
    }
    
    mach_vm_write(target_task, remote_stack, (vm_offset_t)stack, (mach_msg_type_number_t)stack_size);
    
    arm_thread_state64_t state = {};
    bzero(&state, sizeof(arm_thread_state64_t));
    
    state.__x[0] = (uint64_t)remote_stack;
    state.__x[2] = (uint64_t)dlsym(RTLD_NEXT, "dlopen");
    state.__x[3] = (uint64_t)(remote_dylib_path_str + 0x100);
    __darwin_arm_thread_state64_set_lr_fptr(state, (void *)0x7171717171717171);
    __darwin_arm_thread_state64_set_pc_fptr(state, make_sym_callable_data(dlsym(RTLD_NEXT, "pthread_create_from_mach_thread")));
    __darwin_arm_thread_state64_set_sp(state, make_sym_callable_data((void *)(remote_stack + (sp * sizeof(uint64_t)))));
    
    if (thread_set_state(remote_thread, ARM_THREAD_STATE64, (thread_state_t)&state, ARM_THREAD_STATE64_COUNT) != KERN_SUCCESS) {
        free(stack);
        printf("failed to set remote thread state. error: %s\n", mach_error_string(errno));
        return;
    }

    thread_resume(remote_thread);
    free(stack);
}


pid_t get_pid_of_process(const char *process_name) {
    
    pid_t pid = -1;
    size_t size;

    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    sysctl(mib, 4, NULL, &size, NULL, 0);
    
    struct kinfo_proc *processes = malloc(size);
    if (processes == NULL) {
        return -1;
    }
    
    sysctl(mib, 4, processes, &size, NULL, 0);
    for (size_t i = 0; i < size / sizeof(struct kinfo_proc); i++) {
        if (strcmp(processes[i].kp_proc.p_comm, process_name) == 0) {
            pid = processes[i].kp_proc.p_pid;
            break;
        }
    }

    free(processes);
    return pid;
}


CFDataRef handle_message(CFMessagePortRef local, SInt32 msgid, CFDataRef data, void *info) {
    
    // Check-in message
    if (msgid == 0xf00dface) {
        printf("Connection to target process is established\n");
        return NULL;
    }
    // XPC message
    else if (msgid != 0xdeadbeef) {
        printf("Received message with unexpected ID: %d\n", msgid);
        return NULL;
    }
    
    if (data == NULL || CFDataGetLength(data) == 0) {
        printf("Received message with no data\n");
        return NULL;
    }
    
    NSData *msgData = [[NSData alloc] initWithData:(__bridge NSData *)data];
    NSString *msg = [[NSString alloc] initWithData:msgData encoding:NSUTF8StringEncoding];
    if (msg == nil) {
        printf("Failed to decode xpc message data\n");
        return NULL;
    }

    printf("%s\n", [msg UTF8String]);
    return NULL;
}


int main(int argc, const char *argv[]) {
    @autoreleasepool {
        
        if (argc < 2) {
            printf("Usage: %s <process name>\n", argv[0]);
            return KERN_FAILURE;
        }

        const char *target_process = argv[1];
        pid_t pid = get_pid_of_process(target_process);
        if (pid == -1) {
            printf("Failed to find PID of %s\n", target_process);
            return KERN_FAILURE;
        }
        
        task_t target_task = MACH_PORT_NULL;
        if (task_for_pid(mach_task_self_, pid, &target_task) != KERN_SUCCESS) {
            printf("task_for_pid(%d) failed\n", (int)pid);
            return KERN_FAILURE;
        }
        
        CFStringRef port_name = (__bridge CFStringRef)[NSString stringWithFormat:@"com.xpcsniffer.%d", pid];
        CFMessagePortRef local_port = CFMessagePortCreateLocal(kCFAllocatorDefault, port_name, (CFMessagePortCallBack)handle_message, NULL, NULL);
        if (local_port == NULL) {
            printf("Failed to create a local message port\n");
            return KERN_FAILURE;
        }
        
        CFRunLoopSourceRef runLoopSource = CFMessagePortCreateRunLoopSource(NULL, local_port, 0);
        if (runLoopSource == NULL) {
            printf("Failed to create runloop source\n");
            CFRelease(local_port);
            return KERN_FAILURE;
        }
        
        CFRunLoopAddSource(CFRunLoopGetCurrent(), runLoopSource, kCFRunLoopDefaultMode);
        
        FILE *fp = fopen("/tmp/xpcsniffer_message.port", "w");
        if (fp == NULL) {
            printf("Failed to write the message port's name to file\n");
            CFRelease(runLoopSource);
            CFRelease(local_port);
            return KERN_FAILURE;
        }
        
        fprintf(fp, "%s", [(__bridge NSString *)port_name UTF8String]);
        fclose(fp);
            
        // TODO: don't hardcode?
        inject_dylib_into_task(target_task, "/Library/MobileSubstrate/DynamicLibraries/XPCSniffer.dylib");
        
        CFRunLoopRun();
        
        CFRelease(runLoopSource);
        CFRelease(local_port);
    }

    return 0;
}
