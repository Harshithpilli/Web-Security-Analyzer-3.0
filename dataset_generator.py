"""
Dataset Generator for Website Security Analyzer
This script generates synthetic datasets to improve the accuracy and precision of the security model.
"""

import numpy as np
import pandas as pd
import random
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt
from datetime import datetime
import os

# Ensure TF logs are quiet
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

def generate_realistic_dataset(n_samples=10000):
    """
    Generate a realistic synthetic dataset for training the website security model
    Features: [uses_https, suspicious_patterns_count, domain_age_days, uses_suspicious_tld, 
              domain_length, uses_ip, redirects, subdomains_count, url_length]
    Labels: 0 for benign, 1 for malicious
    """
    print(f"Generating {n_samples} samples for training...")
    
    X = []
    y = []
    
    for i in range(n_samples):
        # Randomly decide if this will be a benign (0) or malicious (1) URL
        is_malicious = random.randint(0, 1)
        
        # Feature 1: uses_https (1 if HTTPS, 0 if HTTP)
        # Benign sites are more likely to use HTTPS
        uses_https = random.choice([0, 1]) if is_malicious else random.choice([0, 1, 1, 1, 1])
        
        # Feature 2: suspicious_patterns_count
        if is_malicious:
            # Malicious sites tend to have more suspicious patterns
            suspicious_patterns_count = random.choices(
                [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 
                weights=[1, 5, 10, 15, 20, 25, 15, 10, 5, 3, 1]
            )[0]
        else:
            # Benign sites typically have fewer suspicious patterns
            suspicious_patterns_count = random.choices(
                [0, 1, 2, 3, 4, 5], 
                weights=[60, 30, 7, 2, 1, 0.5]
            )[0]
        
        # Feature 3: domain_age_days
        if is_malicious:
            # Malicious sites often have newer domains
            domain_age_days = random.choices(
                range(1, 180), 
                weights=[i*0.9 for i in range(179, 0, -1)]
            )[0]
        else:
            # Benign sites often have older domains
            domain_age_days = random.choices(
                range(30, 10000), 
                weights=[1 for _ in range(9970)]
            )[0]
        
        # Feature 4: uses_suspicious_tld (1 if suspicious TLD, 0 otherwise)
        uses_suspicious_tld = random.choice([0, 1]) if is_malicious else random.choice([0, 0, 0, 1])
        
        # Feature 5: domain_length
        if is_malicious:
            # Malicious sites sometimes have longer domains to obfuscate
            domain_length = random.randint(10, 50)
        else:
            domain_length = random.randint(3, 25)
        
        # Feature 6: uses_ip (1 if URL uses IP, 0 otherwise)
        uses_ip = random.choice([0, 1]) if is_malicious else random.choice([0, 0, 0, 1])
        
        # Feature 7: redirects
        if is_malicious:
            # Malicious sites often have more redirects
            redirects = random.choices(
                range(0, 10), 
                weights=[30, 20, 15, 10, 8, 5, 4, 3, 3, 2]
            )[0]
        else:
            redirects = random.choices(
                range(0, 5), 
                weights=[50, 30, 15, 4, 1]
            )[0]
        
        # Feature 8: subdomains_count
        if is_malicious:
            # Malicious sites sometimes use many subdomains
            subdomains_count = random.randint(0, 5)
        else:
            subdomains_count = random.randint(0, 2)
        
        # Feature 9: url_length
        if is_malicious:
            # Malicious URLs are often longer due to obfuscation
            url_length = random.randint(50, 200)
        else:
            url_length = random.randint(10, 80)
        
        X.append([
            uses_https, suspicious_patterns_count, domain_age_days, uses_suspicious_tld, 
            domain_length, uses_ip, redirects, subdomains_count, url_length
        ])
        y.append(is_malicious)
    
    return np.array(X, dtype='float32'), np.array(y, dtype='float32')

def analyze_dataset(X, y):
    """Analyze the generated dataset and print statistics"""
    print("\nDataset Analysis:")
    print(f"Total samples: {len(X)}")
    print(f"Feature dimensions: {X.shape[1]}")
    print(f"Malicious samples: {sum(y)} ({sum(y)/len(y)*100:.2f}%)")
    print(f"Benign samples: {len(y)-sum(y)} ({(len(y)-sum(y))/len(y)*100:.2f}%)")
    
    # Feature statistics
    feature_names = [
        'uses_https', 'suspicious_patterns_count', 'domain_age_days', 'uses_suspicious_tld',
        'domain_length', 'uses_ip', 'redirects', 'subdomains_count', 'url_length'
    ]
    
    print("\nFeature Statistics (by class):")
    df = pd.DataFrame(X, columns=feature_names)
    df['label'] = y
    
    for feature in feature_names:
        benign_mean = df[df['label'] == 0][feature].mean()
        malicious_mean = df[df['label'] == 1][feature].mean()
        print(f"{feature}: Benign mean={benign_mean:.2f}, Malicious mean={malicious_mean:.2f}")

def visualize_dataset(X, y):
    """Create visualizations of the dataset"""
    feature_names = [
        'uses_https', 'suspicious_patterns_count', 'domain_age_days', 'uses_suspicious_tld',
        'domain_length', 'uses_ip', 'redirects', 'subdomains_count', 'url_length'
    ]
    
    df = pd.DataFrame(X, columns=feature_names)
    df['label'] = y
    
    # Create histograms for key features by class
    fig, axes = plt.subplots(3, 3, figsize=(15, 12))
    axes = axes.ravel()
    
    for i, feature in enumerate(feature_names):
        df_benign = df[df['label'] == 0][feature]
        df_malicious = df[df['label'] == 1][feature]
        
        axes[i].hist([df_benign, df_malicious], bins=20, alpha=0.7, 
                     label=['Benign', 'Malicious'], color=['green', 'red'])
        axes[i].set_title(f'{feature}')
        axes[i].legend()
    
    plt.tight_layout()
    plt.savefig('feature_distributions.png', dpi=300, bbox_inches='tight')
    plt.close()

def save_dataset(X, y, filename='synthetic_security_dataset.csv'):
    """Save the generated dataset to a CSV file"""
    feature_names = [
        'uses_https', 'suspicious_patterns_count', 'domain_age_days', 'uses_suspicious_tld',
        'domain_length', 'uses_ip', 'redirects', 'subdomains_count', 'url_length', 'label'
    ]
    
    df = pd.DataFrame(X, columns=feature_names[:-1])
    df['label'] = y
    
    df.to_csv(filename, index=False)
    print(f"\nDataset saved to {filename}")
    print(f"Dataset shape: {df.shape}")

def main():
    print("Website Security Analyzer - Synthetic Dataset Generator")
    print("=" * 60)
    
    # Generate dataset
    X, y = generate_realistic_dataset(n_samples=10000)
    
    # Analyze dataset
    analyze_dataset(X, y)
    
    # Create visualizations
    print("\nCreating visualizations...")
    visualize_dataset(X, y)
    print("Visualizations saved as 'correlation_matrix.png' and 'feature_distributions.png'")
    
    # Save dataset
    save_dataset(X, y)
    
    # Show sample of the data
    print("\nSample of generated data:")
    feature_names = [
        'uses_https', 'suspicious_patterns_count', 'domain_age_days', 'uses_suspicious_tld',
        'domain_length', 'uses_ip', 'redirects', 'subdomains_count', 'url_length'
    ]
    
    sample_df = pd.DataFrame(X[:10], columns=feature_names)
    sample_df['label'] = y[:10]
    print(sample_df)
    
    print("\nDataset generation completed successfully!")
    print("The synthetic dataset can now be used to train and improve the security model.")

if __name__ == "__main__":
    main()