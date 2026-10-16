import SwiftUI
import Tailcat

@main
struct TailcatDemoApp: App {
    var body: some Scene { WindowGroup { DemoView() } }
}

struct DemoView: View {
    @State private var address = ""
    @State private var message = "Hello from Swift"
    @State private var result = ""
    @State private var busy = false
    @State private var server: TailcatServer?
    @State private var echoTask: Task<Void, Never>?

    var body: some View {
        Form {
            Section("Tailcat address") {
                TextField("tc…", text: $address, axis: .vertical)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                Button("Start echo server") { startServer() }.disabled(busy || server != nil)
                Text("Share this address privately with the connecting app.").font(.footnote)
            }
            Section("Send to TCP port 8080") {
                TextField("Message", text: $message)
                Button("Connect and echo") { echo() }.disabled(busy || address.isEmpty)
                Text(result).textSelection(.enabled)
            }
            if busy { ProgressView() }
        }
        .navigationTitle("Tailcat Swift")
        .onDisappear {
            echoTask?.cancel()
            if let server { Task { await server.close() } }
        }
    }
    private func startServer() {
        busy = true
        echoTask = Task {
            let instance = TailcatServer()
            do {
                let listener = try await instance.listen(port: 8080)
                address = try await instance.address.description; server = instance; busy = false
                while !Task.isCancelled {
                    let stream = try await listener.accept()
                    Task {
                        do {
                            while true { let data = try await stream.read(); if data.isEmpty { break }; try await stream.write(data) }
                            try await stream.closeWrite()
                        } catch {}
                        await stream.close()
                    }
                }
            } catch { result = String(describing: error); busy = false; await instance.close() }
        }
    }
    private func echo() {
        busy = true
        Task {
            var client: TailcatClient?
            do {
                let connected = try await TailcatClient.connect(to: address); client = connected
                let stream = try await connected.openTCP(port: 8080)
                try await stream.write(Data(message.utf8)); try await stream.closeWrite()
                var response = Data()
                while true { let data = try await stream.read(); if data.isEmpty { break }; response.append(data) }
                result = String(decoding: response, as: UTF8.self)
                await stream.close()
            } catch { result = String(describing: error) }
            await client?.close(); busy = false
        }
    }
}