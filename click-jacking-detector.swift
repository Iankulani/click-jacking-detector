import Foundation

// Function to check if the website has protections against clickjacking
func checkClickjackingProtection(url: String) {
    // Create a URL object
    guard let urlObject = URL(string: url) else {
        print("Invalid URL.")
        return
    }

    // Create a URL request
    var request = URLRequest(url: urlObject)
    request.httpMethod = "GET"
    
    // Create a URLSession to perform the request
    let task = URLSession.shared.dataTask(with: request) { data, response, error in
        // Handle error
        if let error = error {
            print("Error checking site: \(error.localizedDescription)")
            return
        }
        
        // Check the response code
        if let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 {
            // Get the response headers
            let headers = httpResponse.allHeaderFields as! [String: String]
            
            // Check for X-Frame-Options header
            if let xFrameOption = headers["X-Frame-Options"] {
                print("X-Frame-Options Header: \(xFrameOption)")
                if xFrameOption.lowercased() == "deny" || xFrameOption.lowercased() == "sameorigin" {
                    print("The site is protected from clickjacking using X-Frame-Options.")
                } else {
                    print("X-Frame-Options is present but not configured securely.")
                }
            } else {
                print("No X-Frame-Options header found! This site might be vulnerable to clickjacking.")
            }

            // Check for Content-Security-Policy header
            if let cspHeader = headers["Content-Security-Policy"] {
                print("Content-Security-Policy Header: \(cspHeader)")
                if cspHeader.lowercased().contains("frame-ancestors") {
                    print("The site is protected from clickjacking using Content-Security-Policy.")
                } else {
                    print("CSP header found but doesn't have 'frame-ancestors' rule.")
                }
            } else {
                print("No Content-Security-Policy header found! This site might be vulnerable to clickjacking.")
            }
        } else {
            print("Error: Received response code \(String(describing: (response as? HTTPURLResponse)?.statusCode)) from the server.")
        }
    }
    
    // Start the network request
    task.resume()
}

func main() {
    print("Clickjacking Attack Detection Tool")
    
    // Get the IP or domain of the website from the user
    print("Please enter the IP address or domain of the website (e.g., http://example.com): ", terminator: "")
    if let ipOrDomain = readLine()?.trimmingCharacters(in: .whitespacesAndNewlines) {
        
        var url = ipOrDomain
        // Ensure the URL starts with http:// or https://
        if !url.hasPrefix("http://") && !url.hasPrefix("https://") {
            url = "http://\(url)"
        }
        
        print("Checking the site: \(url)")
        checkClickjackingProtection(url: url)
        
        // Run the run loop to wait for async task to complete
        RunLoop.main.run()
    } else {
        print("Invalid input. Please enter a valid URL.")
    }
}

// Run the main function
main()
