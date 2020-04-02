//
//  ViewController.swift
//  OauthSample
//
//  Created by Jane Abraham on 01/04/20.
//  Copyright © 2020 Jane Abraham. All rights reserved.
//

import UIKit
import AppAuth
import QuartzCore

typealias PostRegistrationCallback = (_ configuration: OIDServiceConfiguration?, _ registrationResponse: OIDRegistrationResponse?) -> Void

let  kClientID: String? = ""

class ViewController: UIViewController {
    
    // MARK: - Outlets
    @IBOutlet weak var authManualButton: UIButton!
    @IBOutlet weak var clearAuthStateButton: UIButton!
    @IBOutlet weak var userInfoButton: UIButton!
    @IBOutlet weak var codeExchangeButton: UIButton!
    @IBOutlet weak var autoAuthButton: UIButton!
    @IBOutlet weak var logTextView: UITextView!
    
    // MARK: - Private variables
    private var authState: OIDAuthState?
    
    // MARK: - LifeCycle Methods
    override func viewDidLoad() {
        super.viewDidLoad()
        
        logTextView.textContainer.lineBreakMode = .byCharWrapping
        logTextView.alwaysBounceVertical = true
        logTextView.text = ""
        updateUI()
    // Do any additional setup after loading the view.
    }
    
    override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(true)
    }
    
    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(true)
    }
    
 // MARK: - Helper Methods
    
    func updateUI() {
        userInfoButton.isEnabled = authState?.isAuthorized ?? false
        clearAuthStateButton.isEnabled = authState != nil
        
        if (authState?.lastAuthorizationResponse.authorizationCode) != nil  && !(authState?.lastTokenResponse == nil) {
            codeExchangeButton.isEnabled = true
        } else{
            codeExchangeButton.isEnabled = false
        }
        // dynamically changes authorize button text depending on authorized state
        if (!(authState != nil)) {
            autoAuthButton.setTitle("Authorize", for: .normal)
            autoAuthButton.setTitle("Authorize", for: .highlighted)
            authManualButton.setTitle("Authorize (Manual)", for: .normal)
            authManualButton.setTitle("Authorize (Manual)", for: .highlighted)

        } else {

            autoAuthButton.setTitle("Re-authorize", for: .normal)
                      autoAuthButton.setTitle("Re-authorize", for: .highlighted)
                      authManualButton.setTitle("Re-authorize (Manual)", for: .normal)
                      authManualButton.setTitle("Re-authorize (Manual)", for: .highlighted)
        }
    }
    
    func saveState() {
        do {
            
            let archivedAuthState = try NSKeyedArchiver.archivedData(withRootObject: authState!, requiringSecureCoding: true)
            UserDefaults.standard.set(archivedAuthState, forKey: Constants.kAppAuthExampleAuthStateKey)
            UserDefaults.standard.synchronize()
        } catch {
            print(error)
        }
    }
    
    func loadState() {
        guard let data = UserDefaults.standard.object(forKey: Constants.kAppAuthExampleAuthStateKey) as? Data else {
                   return
               }

               if let authState = NSKeyedUnarchiver.unarchiveObject(with: data) as? OIDAuthState {
                   self.setAuthState(authState)
               }
    }
    
    func stateChanged() {
        saveState()
        updateUI()
    }
    
    func setAuthState(_ authState: OIDAuthState?) {
        if self.authState == authState {
            return
        }
        self.authState = authState
        self.authState?.stateChangeDelegate = self
        stateChanged()
    }
    
    func logMessage(_ message: String?) {

        guard let message = message else {
            return
        }

        print(message);

        let dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "hh:mm:ss";
        let dateString = dateFormatter.string(from: Date())

        // appends to output log
        DispatchQueue.main.async {
            let logText = "\(self.logTextView.text ?? "")\n\(dateString): \(message)"
            self.logTextView.text = logText
        }
    }
    
// MARK: -  Custom Button Actions
    
    @IBAction func autoAuthorize(_ sender: UIButton) {
        
        guard let issuer = URL(string: Constants.kIssuer) else {
            self.logMessage("Error creating URL for : \(Constants.kIssuer)")
            return
        }

        self.logMessage("Fetching configuration for issuer: \(issuer)")

        // discovers endpoints
        OIDAuthorizationService.discoverConfiguration(forIssuer: issuer) { configuration, error in

            guard let config = configuration else {
                self.logMessage("Error retrieving discovery document: \(error?.localizedDescription ?? "DEFAULT_ERROR")")
                self.setAuthState(nil)
                return
            }

            self.logMessage("Got configuration: \(config)")

            if let clientId = kClientID  {
                self.doAuthWithAutoCodeExchange(configuration: config, clientID: clientId, clientSecret: nil)
            } else {
                self.doClientRegistration(configuration: config) { configuration, response in

                    guard let configuration = configuration, let clientID = response?.clientID else {
                        self.logMessage("Error retrieving configuration OR clientID")
                        return
                    }

                    self.doAuthWithAutoCodeExchange(configuration: configuration,
                                                    clientID: clientID,
                                                    clientSecret: response?.clientSecret)
                }
            }
        }

    }
    
    @IBAction func autorizeManually(_ sender: UIButton) {
        
        guard let issuer = URL(string: Constants.kIssuer) else {
            self.logMessage("Error creating URL for : \(Constants.kIssuer)")
            return
        }

        self.logMessage("Fetching configuration for issuer: \(issuer)")

        OIDAuthorizationService.discoverConfiguration(forIssuer: issuer) { configuration, error in

            if let error = error  {
                self.logMessage("Error retrieving discovery document: \(error.localizedDescription)")
                return
            }

            guard let configuration = configuration else {
                self.logMessage("Error retrieving discovery document. Error & Configuration both are NIL!")
                return
            }

            self.logMessage("Got configuration: \(configuration)")

            if let clientId = kClientID {

                self.doAuthWithoutCodeExchange(configuration: configuration, clientID: clientId, clientSecret: nil)

            } else {

                self.doClientRegistration(configuration: configuration) { configuration, response in

                    guard let configuration = configuration, let response = response else {
                        return
                    }

                    self.doAuthWithoutCodeExchange(configuration: configuration,
                                                   clientID: response.clientID,
                                                   clientSecret: response.clientSecret)
                }
            }
        }
    }
    
    @IBAction func exchangeCode(_ sender: Any) {
        guard let tokenExchangeRequest = self.authState?.lastAuthorizationResponse.tokenExchangeRequest() else {
            self.logMessage("Error creating authorization code exchange request")
            return
        }

        self.logMessage("Performing authorization code exchange with request \(tokenExchangeRequest)")

        OIDAuthorizationService.perform(tokenExchangeRequest) { response, error in

            if let tokenResponse = response {
                self.logMessage("Received token response with accessToken: \(tokenResponse.accessToken ?? "DEFAULT_TOKEN")")
            } else {
                self.logMessage("Token exchange error: \(error?.localizedDescription ?? "DEFAULT_ERROR")")
            }
            self.authState?.update(with: response, error: error)
        }
    }
    
    @IBAction func getUserInfo(_ sender: Any) {
        guard let userinfoEndpoint =  self.authState?.lastAuthorizationResponse.request.configuration.discoveryDocument?.userinfoEndpoint else {
                   self.logMessage("Userinfo endpoint not declared in discovery document")
                   return
               }
               self.logMessage("Performing userinfo request")

               let currentAccessToken: String? = self.authState?.lastTokenResponse?.accessToken

               self.authState?.performAction() { (accessToken, idToken, error) in

                   if error != nil  {
                       self.logMessage("Error fetching fresh tokens: \(error?.localizedDescription ?? "ERROR")")
                       return
                   }

                   guard let accessToken = accessToken else {
                       self.logMessage("Error getting accessToken")
                       return
                   }

                   if currentAccessToken != accessToken {
                       self.logMessage("Access token was refreshed automatically (\(currentAccessToken ?? "CURRENT_ACCESS_TOKEN") to \(accessToken))")
                   } else {
                       self.logMessage("Access token was fresh and not updated \(accessToken)")
                   }

                var urlRequest = URLRequest(url: userinfoEndpoint)
                urlRequest.allHTTPHeaderFields = ["Authorization":"Bearer \(accessToken)"]

                   let task = URLSession.shared.dataTask(with: urlRequest) { data, response, error in

                       DispatchQueue.main.async {
                           
                           guard error == nil else {
                               self.logMessage("HTTP request failed \(error?.localizedDescription ?? "ERROR")")
                               return
                           }

                           guard let response = response as? HTTPURLResponse else {
                               self.logMessage("Non-HTTP response")
                               return
                           }

                           guard let data = data else {
                               self.logMessage("HTTP response data is empty")
                               return
                           }

                           var json: [AnyHashable: Any]?

                           do {
                               json = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any]
                           } catch {
                               self.logMessage("JSON Serialization Error")
                           }

                           if response.statusCode != 200 {
                               // server replied with an error
                               let responseText: String? = String(data: data, encoding: String.Encoding.utf8)

                               if response.statusCode == 401 {
                                   // "401 Unauthorized" generally indicates there is an issue with the authorization
                                   // grant. Puts OIDAuthState into an error state.
                                   let oauthError = OIDErrorUtilities.resourceServerAuthorizationError(withCode: 0,
                                                                                                       errorResponse: json,
                                                                                                       underlyingError: error)
                                   self.authState?.update(withAuthorizationError: oauthError)
                                   self.logMessage("Authorization Error (\(oauthError)). Response: \(responseText ?? "RESPONSE_TEXT")")
                               } else {
                                   self.logMessage("HTTP: \(response.statusCode), Response: \(responseText ?? "RESPONSE_TEXT")")
                               }

                               return
                           }

                           if let json = json {
                               self.logMessage("Success: \(json)")
                           }
                       }
                   }

                   task.resume()
               }
        
    }
    
    @IBAction func clearAuthState(_ sender: Any) {
        setAuthState(nil)
    }
    
    @IBAction func clearLog(_ sender: Any) {
        logTextView.text = ""

    }
}

extension ViewController: OIDAuthStateChangeDelegate, OIDAuthStateErrorDelegate {
    
    func didChange(_ state: OIDAuthState) {
        stateChanged()
    }
    
    func authState(_ state: OIDAuthState, didEncounterAuthorizationError error: Error) {
       print("Received authorization error:", error)
    }
    
}

// MARK: -  AppAuth Methods

extension ViewController {
    func doClientRegistration(configuration: OIDServiceConfiguration, callback: @escaping PostRegistrationCallback) {

        guard let redirectURI = URL(string: Constants.kRedirectURI) else {
            self.logMessage("Error creating URL for : \(Constants.kRedirectURI)")
            return
        }

        let request: OIDRegistrationRequest = OIDRegistrationRequest(configuration: configuration,
                                                                     redirectURIs: [redirectURI],
                                                                     responseTypes: nil,
                                                                     grantTypes: nil,
                                                                     subjectType: nil,
                                                                     tokenEndpointAuthMethod: "client_secret_post",
                                                                     additionalParameters: nil)

        // performs registration request
        self.logMessage("Initiating registration request")

        OIDAuthorizationService.perform(request) { response, error in

            if let regResponse = response {
                self.setAuthState(OIDAuthState(registrationResponse: regResponse))
                self.logMessage("Got registration response: \(regResponse)")
                callback(configuration, regResponse)
            } else {
                self.logMessage("Registration error: \(error?.localizedDescription ?? "DEFAULT_ERROR")")
                self.setAuthState(nil)
            }
        }
    }
    
    func doAuthWithAutoCodeExchange(configuration: OIDServiceConfiguration, clientID: String, clientSecret: String?) {

        guard let redirectURI = URL(string: Constants.kRedirectURI) else {
            self.logMessage("Error creating URL for : \(Constants.kRedirectURI)")
               return
           }

           guard let appDelegate = UIApplication.shared.delegate as? AppDelegate else {
               self.logMessage("Error accessing AppDelegate")
               return
           }

           // builds authentication request
           let request = OIDAuthorizationRequest(configuration: configuration,
                                                 clientId: clientID,
                                                 clientSecret: clientSecret,
                                                 scopes:[OIDScopeOpenID, OIDScopeProfile],
                                                 redirectURL: redirectURI,
                                                 responseType: OIDResponseTypeCode,
                                                 additionalParameters: nil)

           // performs authentication request
           logMessage("Initiating authorization request with scope: \(request.scope ?? "DEFAULT_SCOPE")")

           appDelegate.currentAuthorizationFlow = OIDAuthState.authState(byPresenting: request, presenting: self) { authState, error in

               if let authState = authState {
                   self.setAuthState(authState)
                   self.logMessage("Got authorization tokens. Access token: \(authState.lastTokenResponse?.accessToken ?? "DEFAULT_TOKEN")")
               } else {
                   self.logMessage("Authorization error: \(error?.localizedDescription ?? "DEFAULT_ERROR")")
                   self.setAuthState(nil)
               }
           }
       }
    
    func doAuthWithoutCodeExchange(configuration: OIDServiceConfiguration, clientID: String, clientSecret: String?) {

        guard let redirectURI = URL(string: Constants.kRedirectURI) else {
            self.logMessage("Error creating URL for : \(Constants.kRedirectURI)")
            return
        }

        guard let appDelegate = UIApplication.shared.delegate as? AppDelegate else {
            self.logMessage("Error accessing AppDelegate")
            return
        }

        // builds authentication request
        let request = OIDAuthorizationRequest(configuration: configuration,
                                              clientId: clientID,
                                              clientSecret: clientSecret,
                                              scopes: [OIDScopeOpenID, OIDScopeProfile],
                                              redirectURL: redirectURI,
                                              responseType: OIDResponseTypeCode,
                                              additionalParameters: nil)

        // performs authentication request
        logMessage("Initiating authorization request with scope: \(request.scope ?? "DEFAULT_SCOPE")")

        appDelegate.currentAuthorizationFlow = OIDAuthorizationService.present(request, presenting: self) { (response, error) in

            if let response = response {
                let authState = OIDAuthState(authorizationResponse: response)
                self.setAuthState(authState)
                self.logMessage("Authorization response with code: \(response.authorizationCode ?? "DEFAULT_CODE")")
                // could just call [self tokenExchange:nil] directly, but will let the user initiate it.
            } else {
                self.logMessage("Authorization error: \(error?.localizedDescription ?? "DEFAULT_ERROR")")
            }
        }
    }
}


