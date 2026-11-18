import AppKit
let app = NSApplication.shared
app.setActivationPolicy(.regular)
final class Sharing: NSObject, NSApplicationDelegate {
    var window: NSWindow!
    var file: URL!
    var picker: NSSharingServicePicker?
    func applicationDidFinishLaunching(_ notification: Notification) {
        guard CommandLine.arguments.count == 2 else { app.terminate(nil); return }
        file = URL(fileURLWithPath: CommandLine.arguments[1])
        window = NSWindow(contentRect: NSRect(x: 0,y: 0,width: 420,height: 150),styleMask: [.titled,.closable],backing: .buffered,defer: false)
        window.title = "PQ Mail — Share public certificates"
        let label = NSTextField(labelWithString: "Public certificates and YubiKey serial/slots only.")
        label.frame = NSRect(x:20,y:95,width:390,height:24);window.contentView?.addSubview(label)
        let button = NSButton(title:"Share certificates…",target:self,action:#selector(share(_:)))
        button.frame=NSRect(x:100,y:40,width:220,height:35);window.contentView?.addSubview(button)
        window.center();window.makeKeyAndOrderFront(nil);app.activate(ignoringOtherApps:true)
    }
    @objc func share(_ sender:NSButton){picker=NSSharingServicePicker(items:[file!]);picker?.show(relativeTo:sender.bounds,of:sender,preferredEdge:.minY)}
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication)->Bool { true }
}
let delegate=Sharing();app.delegate=delegate;app.run()
