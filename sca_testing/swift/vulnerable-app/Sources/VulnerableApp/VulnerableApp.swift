import Foundation
// Vulnerable dependencies
import Alamofire
import SwiftyJSON
import Kingfisher
import RealmSwift
import SnapKit
import RxSwift

// Healthy dependencies
import Vapor
import AsyncHTTPClient
import ArgumentParser
import Logging
import Crypto

/// Main application class demonstrating usage of vulnerable and healthy packages
public class VulnerableApp {

    // MARK: - Properties

    private let disposeBag = DisposeBag()
    private var logger: Logger

    public init() {
        self.logger = Logger(label: "com.test.vulnerableapp")
    }

    // MARK: - Vulnerable Network Requests using Alamofire

    /// Demonstrates vulnerable Alamofire usage (v4.9.0 has CVE-2019-8331)
    public func makeVulnerableNetworkRequest() {
        AF.request("https://api.example.com/data")
            .validate()
            .responseJSON { response in
                switch response.result {
                case .success(let value):
                    // Vulnerable JSON parsing with SwiftyJSON
                    let json = JSON(value)
                    self.parseVulnerableJSON(json)
                case .failure(let error):
                    print("Request failed: \(error)")
                }
            }
    }

    /// Demonstrates vulnerable JSON parsing with SwiftyJSON
    private func parseVulnerableJSON(_ json: JSON) {
        // SwiftyJSON v4.0.0 has parsing vulnerabilities
        let name = json["user"]["name"].stringValue
        let email = json["user"]["email"].stringValue
        print("User: \(name), Email: \(email)")
    }

    // MARK: - Vulnerable Image Loading using Kingfisher

    #if canImport(UIKit)
    import UIKit

    /// Demonstrates vulnerable image loading with Kingfisher v5.0.0
    public func loadVulnerableImage(url: URL, into imageView: UIImageView) {
        // Kingfisher v5.0.0 has image loading vulnerabilities
        imageView.kf.setImage(with: url) { result in
            switch result {
            case .success(let value):
                print("Image loaded: \(value.source.url?.absoluteString ?? "")")
            case .failure(let error):
                print("Image loading failed: \(error)")
            }
        }
    }
    #endif

    // MARK: - Vulnerable Database Operations using Realm

    /// Demonstrates vulnerable Realm usage (v5.0.0 has data corruption issues)
    public func vulnerableRealmOperations() {
        do {
            let realm = try Realm()

            // Define a simple model
            class User: Object {
                @objc dynamic var id = 0
                @objc dynamic var name = ""
                @objc dynamic var email = ""
            }

            // Write operation with vulnerable Realm version
            try realm.write {
                let user = User()
                user.id = 1
                user.name = "Vulnerable User"
                user.email = "user@example.com"
                realm.add(user)
            }

            // Query operation
            let users = realm.objects(User.self)
            print("Found \(users.count) users")

        } catch {
            print("Realm error: \(error)")
        }
    }

    // MARK: - Vulnerable Reactive Programming using RxSwift

    /// Demonstrates RxSwift v5.0.0 with memory leak issues
    public func vulnerableReactiveCode() {
        let subject = PublishSubject<String>()

        // RxSwift v5.0.0 has potential memory leak issues
        subject
            .subscribe(onNext: { value in
                print("Received: \(value)")
            })
            .disposed(by: disposeBag)

        subject.onNext("Vulnerable reactive event")
    }

    // MARK: - Healthy Network Requests using AsyncHTTPClient

    /// Demonstrates healthy HTTP client usage
    public func makeHealthyNetworkRequest() async throws {
        let httpClient = HTTPClient(eventLoopGroupProvider: .createNew)
        defer {
            try? httpClient.syncShutdown()
        }

        let request = HTTPClientRequest(url: "https://api.example.com/data")
        let response = try await httpClient.execute(request, timeout: .seconds(30))

        if response.status == .ok {
            let body = try await response.body.collect(upTo: 1024 * 1024)
            logger.info("Healthy request succeeded", metadata: ["size": "\(body.readableBytes)"])
        }
    }

    // MARK: - Healthy Cryptography using Swift Crypto

    /// Demonstrates secure cryptography with Swift Crypto
    public func performHealthyCryptography() {
        let key = SymmetricKey(size: .bits256)
        let data = "Sensitive data".data(using: .utf8)!

        do {
            let sealedBox = try AES.GCM.seal(data, using: key)
            logger.info("Data encrypted successfully")

            let decryptedData = try AES.GCM.open(sealedBox, using: key)
            let decryptedString = String(data: decryptedData, encoding: .utf8)
            logger.info("Data decrypted: \(decryptedString ?? "N/A")")
        } catch {
            logger.error("Cryptography error: \(error)")
        }
    }

    // MARK: - Healthy Logging

    /// Demonstrates healthy logging practices
    public func performHealthyLogging() {
        logger.info("Application started")
        logger.debug("Debug information", metadata: ["component": "VulnerableApp"])
        logger.warning("Warning message")
        logger.error("Error occurred", metadata: ["error_code": "500"])
    }

    // MARK: - Public Interface

    public func runAllExamples() {
        print("=== Running Vulnerable Examples ===")
        makeVulnerableNetworkRequest()
        vulnerableRealmOperations()
        vulnerableReactiveCode()

        print("\n=== Running Healthy Examples ===")
        performHealthyLogging()
        performHealthyCryptography()

        Task {
            try? await makeHealthyNetworkRequest()
        }
    }
}

// MARK: - CLI Tool using ArgumentParser (Healthy)

@main
struct VulnerableCLI: AsyncParsableCommand {
    static var configuration = CommandConfiguration(
        commandName: "vulnerable-app",
        abstract: "A Swift application with vulnerable and healthy dependencies for SCA testing"
    )

    @Flag(help: "Run all vulnerability examples")
    var runVulnerable = false

    @Flag(help: "Run all healthy examples")
    var runHealthy = false

    func run() async throws {
        let app = VulnerableApp()

        if runVulnerable {
            print("Running vulnerable dependency examples...")
            app.makeVulnerableNetworkRequest()
            app.vulnerableRealmOperations()
            app.vulnerableReactiveCode()
        }

        if runHealthy {
            print("Running healthy dependency examples...")
            app.performHealthyLogging()
            app.performHealthyCryptography()
            try await app.makeHealthyNetworkRequest()
        }

        if !runVulnerable && !runHealthy {
            print("Use --run-vulnerable or --run-healthy flags")
            app.runAllExamples()
        }
    }
}
