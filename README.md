# Website Security Analyzer 3.0

Welcome to the Advanced Website Security Analyzer! This is a friendly, Python-based tool designed to help you quickly assess the security of websites. By combining tried-and-true heuristic checks with a smart machine learning model, this tool helps you spot potentially malicious websites before they can cause trouble.

## What It Does

- **Heuristic Security Checks**
  - **HTTPS Check:** Quickly tells you if the website is using secure HTTPS.
  - **Suspicious Patterns:** Scans the URL for red flags like common malicious patterns and keywords.
  - **Domain Age Analysis:** Looks up the domain's age using WHOIS data to see if it's a new, and potentially risky, site.
  - **SSL Certificate Validation:** Checks if the site's SSL certificate is valid.
  - **HTML Content Analysis:** Scans the website's code for any suspicious HTML or JavaScript.
  - **OWASP Vulnerability Checks:** Simulates tests for common web vulnerabilities like SQL injection or XSS.

- **Machine Learning Magic**
  - Uses a TensorFlow model that has been trained on real-world examples to predict if a URL might be malicious.
  - Combines the ML prediction with heuristic scores to give you an overall risk rating.
  - Offers insights on which factors influenced the ML prediction the most.

- **Performance & Visual Insights**
  - Runs several checks at once for faster results.
  - Creates a neat bar chart (`heuristic_scores.png`) to show you the scores for each security check.
  - Features an interactive CLI built with the Rich library, making the tool both fun and easy to use.

- **Continuous Learning**
  - You can provide feedback on the analysis results, which helps retrain and improve the machine learning model over time.

## Key Improvements

### 1. Synthetic Dataset Generation
- **Function Added**: `_generate_synthetic_dataset(n_samples=10000)`
- **Purpose**: Generate realistic training data with 10,000 samples instead of the original 20 samples
- **Features Generated**:
  - `uses_https`: 1 if HTTPS, 0 if HTTP (realistic distributions for malicious/benign sites)
  - `suspicious_patterns_count`: Count of suspicious URL patterns (higher for malicious sites)
  - `domain_age_days`: Age of domain registration (newer for malicious sites)
  - `uses_suspicious_tld`: 1 if using suspicious TLD, 0 otherwise
  - `domain_length`: Length of domain name (longer for malicious sites)
  - `uses_ip`: 1 if URL uses IP address instead of domain, 0 otherwise
  - `redirects`: Number of redirects in URL chain
  - `subdomains_count`: Number of subdomains
  - `url_length`: Total length of URL

### 2. Enhanced Neural Network Architecture
- **Previous Architecture**: Simple 3-layer network (16→8→1 neurons)
- **New Architecture**: 6-layer network with dropout for regularization
  - Input layer (9 features)
  - Dense layer (64 neurons, ReLU activation)
  - Dropout layer (30% dropout rate)
  - Dense layer (32 neurons, ReLU activation)
  - Dropout layer (30% dropout rate)
  - Dense layer (16 neurons, ReLU activation)
  - Output layer (1 neuron, sigmoid activation)
- **Benefits**: More complex representations, reduced overfitting

### 3. Feature Scaling Implementation
- **Added**: StandardScaler for feature normalization
- **Training**: Features are standardized during model training
- **Prediction**: Same scaling applied during inference
- **Benefit**: Improved model convergence and performance

### 4. Improved Training Process
- **Validation Split**: 80% train, 20% validation
- **Early Stopping**: Monitors validation loss with patience=10
- **Multiple Metrics**: Accuracy, precision, and recall tracked
- **Optimizer**: Adam with learning rate 0.001
- **Loss Function**: Binary crossentropy

### 5. Enhanced Retraining Process
- **Synthetic Data Combination**: New training data combined with 5000 synthetic samples
- **Prevents Catastrophic Forgetting**: Maintains knowledge of previous patterns
- **Improved Architecture**: Uses same enhanced network as initial training
- **Proper Scaling**: Combined data is scaled with updated scaler

### 6. Web Frontend Interface
- **Flask Application**: Web-based interface for easy URL analysis
- **Interactive Dashboard**: Real-time results display with risk visualization
- **User Feedback System**: Interface to provide feedback for model improvement
- **Responsive Design**: Works on desktop and mobile devices

## Getting Started

### Installation

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/Harshithpilli/WebsiteSecurityAnalzyer-3.0.git
   cd WebsiteSecurityAnalzyer-3.0
   ```

2. **Install the Required Libraries:**
   ```bash
   pip install tensorflow requests python-whois tldextract numpy pandas matplotlib beautifulsoup4 rich flask
   ```

You'll need packages like TensorFlow, Requests, WHOIS, tldextract, NumPy, Pandas, Matplotlib, BeautifulSoup4, Rich, and Flask.

3. **Optional Configuration:**
The tool disables oneDNN optimizations for TensorFlow by setting:

```bash
os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"
```

## How To Run

### Option 1: Command Line Interface

**Interactive Mode**
Just run the tool without any arguments, and you'll enter an easy-to-use interactive menu:
```bash
python security_analzyer_3.py
```
You can choose to:
- Analyze a URL
- Provide feedback to help improve the model
- Exit the tool

### Option 2: Web Interface

**Start the Web Application**
Run the following command to start the Flask web server:
```bash
python app.py
```
This will launch the application and open your browser to `http://localhost:5000`

**Web Interface Features:**
- Clean, responsive user interface
- Real-time URL analysis
- Visual risk score display
- Detailed heuristic checks table
- Security details listing
- User feedback options to improve the model

### What the Output Looks Like

**Risk Score:** A final score out of 10 that tells you how risky the website might be.

**Risk Level:** Categorized as Low, Medium, or High Risk.

**Details:** A clear breakdown of what was checked and why.

**Visualization:** A bar chart (heuristic_scores.png) that visualizes the scores from each security check.

## Inside the Code

**Main Class:**
The WebsiteSecurityAnalyzer class is the heart of the tool. It handles all the security checks and ML predictions.

**Security Checks:**
Each security check (like HTTPS verification or SSL certificate validation) is done by its own function, making the code modular and easy to understand.

**Machine Learning:**
The tool trains a TensorFlow model to help predict if a URL is malicious. It can also be retrained with your feedback to get even better over time.

**Web Interface:**
The Flask application provides a user-friendly web interface for the security analyzer, making it accessible to users without command-line experience.
